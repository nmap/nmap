/*
 *  pcap-linux.c: Packet capture interface to the Linux kernel
 *
 *  Copyright (c) 2000 Torsten Landschoff <torsten@debian.org>
 *		       Sebastian Krahmer  <krahmer@cs.uni-potsdam.de>
 *
 *  License: BSD
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. The names of the authors may not be used to endorse or promote
 *     products derived from this software without specific prior
 *     written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  Modifications:     Added PACKET_MMAP support
 *                     Paolo Abeni <paolo.abeni@email.it>
 *                     Added TPACKET_V3 support
 *                     Gabor Tatarka <gabor.tatarka@ericsson.com>
 *
 *                     based on previous works of:
 *                     Simon Patarin <patarin@cs.unibo.it>
 *                     Phil Wood <cpw@lanl.gov>
 *
 * Monitor-mode support for mac80211 includes code taken from the iw
 * command; the copyright notice for that code is
 *
 * Copyright (c) 2007, 2008	Johannes Berg
 * Copyright (c) 2007		Andy Lutomirski
 * Copyright (c) 2007		Mike Kershaw
 * Copyright (c) 2008		Gábor Stefanik
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#define _GNU_SOURCE

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <endian.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <poll.h>
#include <dirent.h>
#include <sys/eventfd.h>

#include "pcap-int.h"
#include "pcap-util.h"
#include "pcap/sll.h"
#include "pcap/vlan.h"
#include "pcap/can_socketcan.h"

#include "diag-control.h"

/*
 * We require TPACKET_V2 support.
 */
#ifndef TPACKET2_HDRLEN
#error "Libpcap will only work if TPACKET_V2 is supported; you must build for a 2.6.27 or later kernel"
#endif

/* check for memory mapped access availability. We assume every needed
 * struct is defined if the macro TPACKET_HDRLEN is defined, because it
 * uses many ring related structs and macros */
#ifdef TPACKET3_HDRLEN
# define HAVE_TPACKET3
#endif /* TPACKET3_HDRLEN */

/*
 * Not all compilers that are used to compile code to run on Linux have
 * these builtins.  For example, older versions of GCC don't, and at
 * least some people are doing cross-builds for MIPS with older versions
 * of GCC.
 */
#ifndef HAVE___ATOMIC_LOAD_N
#define __atomic_load_n(ptr, memory_model)		(*(ptr))
#endif
#ifndef HAVE___ATOMIC_STORE_N
#define __atomic_store_n(ptr, val, memory_model)	*(ptr) = (val)
#endif

#define packet_mmap_acquire(pkt) \
	(__atomic_load_n(&pkt->tp_status, __ATOMIC_ACQUIRE) != TP_STATUS_KERNEL)
#define packet_mmap_release(pkt) \
	(__atomic_store_n(&pkt->tp_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE))
#define packet_mmap_v3_acquire(pkt) \
	(__atomic_load_n(&pkt->hdr.bh1.block_status, __ATOMIC_ACQUIRE) != TP_STATUS_KERNEL)
#define packet_mmap_v3_release(pkt) \
	(__atomic_store_n(&pkt->hdr.bh1.block_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE))

#include <linux/types.h>
#include <linux/filter.h>

#ifdef HAVE_LINUX_NET_TSTAMP_H
#include <linux/net_tstamp.h>
#endif

/*
 * For checking whether a device is a bonding device.
 */
#include <linux/if_bonding.h>

/*
 * Got libnl?
 */
#ifdef HAVE_LIBNL
#include <linux/nl80211.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#endif /* HAVE_LIBNL */

#ifndef HAVE_SOCKLEN_T
typedef int		socklen_t;
#endif

#define MAX_LINKHEADER_SIZE	256

/*
 * When capturing on all interfaces we use this as the buffer size.
 * Should be bigger then all MTUs that occur in real life.
 * 64kB should be enough for now.
 */
#define BIGGER_THAN_ALL_MTUS	(64*1024)

/*
 * Private data for capturing on Linux PF_PACKET sockets.
 */
struct pcap_linux {
	long long sysfs_dropped; /* packets reported dropped by /sys/class/net/{if_name}/statistics/rx_{missed,fifo}_errors */
	struct pcap_stat stat;

	char	*device;	/* device name */
	int	filter_in_userland; /* must filter in userland */
	int	blocks_to_filter_in_userland;
	int	must_do_on_close; /* stuff we must do when we close */
	int	timeout;	/* timeout for buffering */
	int	cooked;		/* using SOCK_DGRAM rather than SOCK_RAW */
	int	ifindex;	/* interface index of device we're bound to */
	int	lo_ifindex;	/* interface index of the loopback device */
	int	netdown;	/* we got an ENETDOWN and haven't resolved it */
	bpf_u_int32 oldmode;	/* mode to restore when turning monitor mode off */
	char	*mondevice;	/* mac80211 monitor device we created */
	u_char	*mmapbuf;	/* memory-mapped region pointer */
	size_t	mmapbuflen;	/* size of region */
	int	vlan_offset;	/* offset at which to insert vlan tags; if -1, don't insert */
	u_int	tp_version;	/* version of tpacket_hdr for mmaped ring */
	u_int	tp_hdrlen;	/* hdrlen of tpacket_hdr for mmaped ring */
	u_char	*oneshot_buffer; /* buffer for copy of packet */
	int	poll_timeout;	/* timeout to use in poll() */
#ifdef HAVE_TPACKET3
	unsigned char *current_packet; /* Current packet within the TPACKET_V3 block. Move to next block if NULL. */
	int packets_left; /* Unhandled packets left within the block from previous call to pcap_read_linux_mmap_v3 in case of TPACKET_V3. */
#endif
	int poll_breakloop_fd; /* fd to an eventfd to break from blocking operations */
};

/*
 * Stuff to do when we close.
 */
#define MUST_CLEAR_RFMON	0x00000001	/* clear rfmon (monitor) mode */
#define MUST_DELETE_MONIF	0x00000002	/* delete monitor-mode interface */

/*
 * Prototypes for internal functions and methods.
 */
static int get_if_flags(const char *, bpf_u_int32 *, char *);
static int is_wifi(const char *);
static int map_arphrd_to_dlt(pcap_t *, int, const char *, int);
static int pcap_activate_linux(pcap_t *);
static int setup_socket(pcap_t *, int);
static int setup_mmapped(pcap_t *);
static int pcap_can_set_rfmon_linux(pcap_t *);
static int pcap_inject_linux(pcap_t *, const void *, int);
static int pcap_stats_linux(pcap_t *, struct pcap_stat *);
static int pcap_setfilter_linux(pcap_t *, struct bpf_program *);
static int pcap_setdirection_linux(pcap_t *, pcap_direction_t);
static int pcap_set_datalink_linux(pcap_t *, int);
static void pcap_cleanup_linux(pcap_t *);

union thdr {
	struct tpacket2_hdr		*h2;
#ifdef HAVE_TPACKET3
	struct tpacket_block_desc	*h3;
#endif
	u_char				*raw;
};

#define RING_GET_FRAME_AT(h, offset) (((u_char **)h->buffer)[(offset)])
#define RING_GET_CURRENT_FRAME(h) RING_GET_FRAME_AT(h, h->offset)

static void destroy_ring(pcap_t *handle);
static int create_ring(pcap_t *handle);
static int prepare_tpacket_socket(pcap_t *handle);
static int pcap_read_linux_mmap_v2(pcap_t *, int, pcap_handler , u_char *);
#ifdef HAVE_TPACKET3
static int pcap_read_linux_mmap_v3(pcap_t *, int, pcap_handler , u_char *);
#endif
static int pcap_setnonblock_linux(pcap_t *p, int nonblock);
static int pcap_getnonblock_linux(pcap_t *p);
static void pcapint_oneshot_linux(u_char *user, const struct pcap_pkthdr *h,
    const u_char *bytes);

/*
 * In pre-3.0 kernels, the tp_vlan_tci field is set to whatever the
 * vlan_tci field in the skbuff is.  0 can either mean "not on a VLAN"
 * or "on VLAN 0".  There is no flag set in the tp_status field to
 * distinguish between them.
 *
 * In 3.0 and later kernels, if there's a VLAN tag present, the tp_vlan_tci
 * field is set to the VLAN tag, and the TP_STATUS_VLAN_VALID flag is set
 * in the tp_status field, otherwise the tp_vlan_tci field is set to 0 and
 * the TP_STATUS_VLAN_VALID flag isn't set in the tp_status field.
 *
 * With a pre-3.0 kernel, we cannot distinguish between packets with no
 * VLAN tag and packets on VLAN 0, so we will mishandle some packets, and
 * there's nothing we can do about that.
 *
 * So, on those systems, which never set the TP_STATUS_VLAN_VALID flag, we
 * continue the behavior of earlier libpcaps, wherein we treated packets
 * with a VLAN tag of 0 as being packets without a VLAN tag rather than packets
 * on VLAN 0.  We do this by treating packets with a tp_vlan_tci of 0 and
 * with the TP_STATUS_VLAN_VALID flag not set in tp_status as not having
 * VLAN tags.  This does the right thing on 3.0 and later kernels, and
 * continues the old unfixably-imperfect behavior on pre-3.0 kernels.
 *
 * If TP_STATUS_VLAN_VALID isn't defined, we test it as the 0x10 bit; it
 * has that value in 3.0 and later kernels.
 */
#ifdef TP_STATUS_VLAN_VALID
  #define VLAN_VALID(hdr, hv)	((hv)->tp_vlan_tci != 0 || ((hdr)->tp_status & TP_STATUS_VLAN_VALID))
#else
  /*
   * This is being compiled on a system that lacks TP_STATUS_VLAN_VALID,
   * so we test with the value it has in the 3.0 and later kernels, so
   * we can test it if we're running on a system that has it.  (If we're
   * running on a system that doesn't have it, it won't be set in the
   * tp_status field, so the tests of it will always fail; that means
   * we behave the way we did before we introduced this macro.)
   */
  #define VLAN_VALID(hdr, hv)	((hv)->tp_vlan_tci != 0 || ((hdr)->tp_status & 0x10))
#endif

#ifdef TP_STATUS_VLAN_TPID_VALID
# define VLAN_TPID(hdr, hv)	(((hv)->tp_vlan_tpid || ((hdr)->tp_status & TP_STATUS_VLAN_TPID_VALID)) ? (hv)->tp_vlan_tpid : ETH_P_8021Q)
#else
# define VLAN_TPID(hdr, hv)	ETH_P_8021Q
#endif

/*
 * Required select timeout if we're polling for an "interface disappeared"
 * indication - 1 millisecond.
 */
static const struct timeval netdown_timeout = {
	0, 1000		/* 1000 microseconds = 1 millisecond */
};

/*
 * Wrap some ioctl calls
 */
static int	iface_get_id(int fd, const char *device, char *ebuf);
static int	iface_get_mtu(int fd, const char *device, char *ebuf);
static int	iface_get_arptype(int fd, const char *device, char *ebuf);
static int	iface_bind(int fd, int ifindex, char *ebuf, int protocol);
static int	enter_rfmon_mode(pcap_t *handle, int sock_fd,
    const char *device);
static int	iface_get_ts_types(const char *device, pcap_t *handle,
    char *ebuf);
static int	iface_get_offload(pcap_t *handle);

static int	fix_program(pcap_t *handle, struct sock_fprog *fcode);
static int	fix_offset(pcap_t *handle, struct bpf_insn *p);
static int	set_kernel_filter(pcap_t *handle, struct sock_fprog *fcode);
static int	reset_kernel_filter(pcap_t *handle);

static struct sock_filter	total_insn
	= BPF_STMT(BPF_RET | BPF_K, 0);
static struct sock_fprog	total_fcode
	= { 1, &total_insn };

static int	iface_dsa_get_proto_info(const char *device, pcap_t *handle);

pcap_t *
pcapint_create_interface(const char *device, char *ebuf)
{
	pcap_t *handle;

	handle = PCAP_CREATE_COMMON(ebuf, struct pcap_linux);
	if (handle == NULL)
		return NULL;

	handle->activate_op = pcap_activate_linux;
	handle->can_set_rfmon_op = pcap_can_set_rfmon_linux;

	/*
	 * See what time stamp types we support.
	 */
	if (iface_get_ts_types(device, handle, ebuf) == -1) {
		pcap_close(handle);
		return NULL;
	}

	/*
	 * We claim that we support microsecond and nanosecond time
	 * stamps.
	 *
	 * XXX - with adapter-supplied time stamps, can we choose
	 * microsecond or nanosecond time stamps on arbitrary
	 * adapters?
	 */
	handle->tstamp_precision_list = malloc(2 * sizeof(u_int));
	if (handle->tstamp_precision_list == NULL) {
		pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		pcap_close(handle);
		return NULL;
	}
	handle->tstamp_precision_list[0] = PCAP_TSTAMP_PRECISION_MICRO;
	handle->tstamp_precision_list[1] = PCAP_TSTAMP_PRECISION_NANO;
	handle->tstamp_precision_count = 2;

	/*
	 * Start out with the breakloop handle not open; we don't
	 * need it until we're activated and ready to capture.
	 */
	struct pcap_linux *handlep = handle->priv;
	handlep->poll_breakloop_fd = -1;

	return handle;
}

#ifdef HAVE_LIBNL
/*
 * If interface {if_name} is a mac80211 driver, the file
 * /sys/class/net/{if_name}/phy80211 is a symlink to
 * /sys/class/ieee80211/{phydev_name}, for some {phydev_name}.
 *
 * On Fedora 9, with a 2.6.26.3-29 kernel, my Zydas stick, at
 * least, has a "wmaster0" device and a "wlan0" device; the
 * latter is the one with the IP address.  Both show up in
 * "tcpdump -D" output.  Capturing on the wmaster0 device
 * captures with 802.11 headers.
 *
 * airmon-ng searches through /sys/class/net for devices named
 * monN, starting with mon0; as soon as one *doesn't* exist,
 * it chooses that as the monitor device name.  If the "iw"
 * command exists, it does
 *
 *    iw dev {if_name} interface add {monif_name} type monitor
 *
 * where {monif_name} is the monitor device.  It then (sigh) sleeps
 * .1 second, and then configures the device up.  Otherwise, if
 * /sys/class/ieee80211/{phydev_name}/add_iface is a file, it writes
 * {mondev_name}, without a newline, to that file, and again (sigh)
 * sleeps .1 second, and then iwconfig's that device into monitor
 * mode and configures it up.  Otherwise, you can't do monitor mode.
 *
 * All these devices are "glued" together by having the
 * /sys/class/net/{if_name}/phy80211 links pointing to the same
 * place, so, given a wmaster, wlan, or mon device, you can
 * find the other devices by looking for devices with
 * the same phy80211 link.
 *
 * To turn monitor mode off, delete the monitor interface,
 * either with
 *
 *    iw dev {monif_name} interface del
 *
 * or by sending {monif_name}, with no NL, down
 * /sys/class/ieee80211/{phydev_name}/remove_iface
 *
 * Note: if you try to create a monitor device named "monN", and
 * there's already a "monN" device, it fails, as least with
 * the netlink interface (which is what iw uses), with a return
 * value of -ENFILE.  (Return values are negative errnos.)  We
 * could probably use that to find an unused device.
 *
 * Yes, you can have multiple monitor devices for a given
 * physical device.
 */

/*
 * Is this a mac80211 device?  If so, fill in the physical device path and
 * return 1; if not, return 0.  On an error, fill in handle->errbuf and
 * return PCAP_ERROR.
 */
static int
get_mac80211_phydev(pcap_t *handle, const char *device, char *phydev_path,
    size_t phydev_max_pathlen)
{
	char *pathstr;
	ssize_t bytes_read;

	/*
	 * Generate the path string for the symlink to the physical device.
	 */
	if (asprintf(&pathstr, "/sys/class/net/%s/phy80211", device) == -1) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: Can't generate path name string for /sys/class/net device",
		    device);
		return PCAP_ERROR;
	}
	bytes_read = readlink(pathstr, phydev_path, phydev_max_pathlen);
	if (bytes_read == -1) {
		if (errno == ENOENT || errno == EINVAL) {
			/*
			 * Doesn't exist, or not a symlink; assume that
			 * means it's not a mac80211 device.
			 */
			free(pathstr);
			return 0;
		}
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "%s: Can't readlink %s", device, pathstr);
		free(pathstr);
		return PCAP_ERROR;
	}
	free(pathstr);
	phydev_path[bytes_read] = '\0';
	return 1;
}

struct nl80211_state {
	struct nl_sock *nl_sock;
	struct nl_cache *nl_cache;
	struct genl_family *nl80211;
};

static int
nl80211_init(pcap_t *handle, struct nl80211_state *state, const char *device)
{
	int err;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: failed to allocate netlink handle", device);
		return PCAP_ERROR;
	}

	if (genl_connect(state->nl_sock)) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: failed to connect to generic netlink", device);
		goto out_handle_destroy;
	}

	err = genl_ctrl_alloc_cache(state->nl_sock, &state->nl_cache);
	if (err < 0) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: failed to allocate generic netlink cache: %s",
		    device, nl_geterror(-err));
		goto out_handle_destroy;
	}

	state->nl80211 = genl_ctrl_search_by_name(state->nl_cache, "nl80211");
	if (!state->nl80211) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: nl80211 not found", device);
		goto out_cache_free;
	}

	return 0;

out_cache_free:
	nl_cache_free(state->nl_cache);
out_handle_destroy:
	nl_socket_free(state->nl_sock);
	return PCAP_ERROR;
}

static void
nl80211_cleanup(struct nl80211_state *state)
{
	genl_family_put(state->nl80211);
	nl_cache_free(state->nl_cache);
	nl_socket_free(state->nl_sock);
}

static int
del_mon_if(pcap_t *handle, int sock_fd, struct nl80211_state *state,
    const char *device, const char *mondevice);

static int
add_mon_if(pcap_t *handle, int sock_fd, struct nl80211_state *state,
    const char *device, const char *mondevice)
{
	struct pcap_linux *handlep = handle->priv;
	int ifindex;
	struct nl_msg *msg;
	int err;

	ifindex = iface_get_id(sock_fd, device, handle->errbuf);
	if (ifindex == -1)
		return PCAP_ERROR;

	msg = nlmsg_alloc();
	if (!msg) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: failed to allocate netlink msg", device);
		return PCAP_ERROR;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(state->nl80211), 0,
		    0, NL80211_CMD_NEW_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
DIAG_OFF_NARROWING
	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, mondevice);
DIAG_ON_NARROWING
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

	err = nl_send_auto_complete(state->nl_sock, msg);
	if (err < 0) {
		if (err == -NLE_FAILURE) {
			/*
			 * Device not available; our caller should just
			 * keep trying.  (libnl 2.x maps ENFILE to
			 * NLE_FAILURE; it can also map other errors
			 * to that, but there's not much we can do
			 * about that.)
			 */
			nlmsg_free(msg);
			return 0;
		} else {
			/*
			 * Real failure, not just "that device is not
			 * available.
			 */
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "%s: nl_send_auto_complete failed adding %s interface: %s",
			    device, mondevice, nl_geterror(-err));
			nlmsg_free(msg);
			return PCAP_ERROR;
		}
	}
	err = nl_wait_for_ack(state->nl_sock);
	if (err < 0) {
		if (err == -NLE_FAILURE) {
			/*
			 * Device not available; our caller should just
			 * keep trying.  (libnl 2.x maps ENFILE to
			 * NLE_FAILURE; it can also map other errors
			 * to that, but there's not much we can do
			 * about that.)
			 */
			nlmsg_free(msg);
			return 0;
		} else {
			/*
			 * Real failure, not just "that device is not
			 * available.
			 */
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "%s: nl_wait_for_ack failed adding %s interface: %s",
			    device, mondevice, nl_geterror(-err));
			nlmsg_free(msg);
			return PCAP_ERROR;
		}
	}

	/*
	 * Success.
	 */
	nlmsg_free(msg);

	/*
	 * Try to remember the monitor device.
	 */
	handlep->mondevice = strdup(mondevice);
	if (handlep->mondevice == NULL) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "strdup");
		/*
		 * Get rid of the monitor device.
		 */
		del_mon_if(handle, sock_fd, state, device, mondevice);
		return PCAP_ERROR;
	}
	return 1;

nla_put_failure:
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
	    "%s: nl_put failed adding %s interface",
	    device, mondevice);
	nlmsg_free(msg);
	return PCAP_ERROR;
}

static int
del_mon_if(pcap_t *handle, int sock_fd, struct nl80211_state *state,
    const char *device, const char *mondevice)
{
	int ifindex;
	struct nl_msg *msg;
	int err;

	ifindex = iface_get_id(sock_fd, mondevice, handle->errbuf);
	if (ifindex == -1)
		return PCAP_ERROR;

	msg = nlmsg_alloc();
	if (!msg) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: failed to allocate netlink msg", device);
		return PCAP_ERROR;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(state->nl80211), 0,
		    0, NL80211_CMD_DEL_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);

	err = nl_send_auto_complete(state->nl_sock, msg);
	if (err < 0) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: nl_send_auto_complete failed deleting %s interface: %s",
		    device, mondevice, nl_geterror(-err));
		nlmsg_free(msg);
		return PCAP_ERROR;
	}
	err = nl_wait_for_ack(state->nl_sock);
	if (err < 0) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: nl_wait_for_ack failed adding %s interface: %s",
		    device, mondevice, nl_geterror(-err));
		nlmsg_free(msg);
		return PCAP_ERROR;
	}

	/*
	 * Success.
	 */
	nlmsg_free(msg);
	return 1;

nla_put_failure:
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
	    "%s: nl_put failed deleting %s interface",
	    device, mondevice);
	nlmsg_free(msg);
	return PCAP_ERROR;
}
#endif /* HAVE_LIBNL */

static int pcap_protocol(pcap_t *handle)
{
	int protocol;

	protocol = handle->opt.protocol;
	if (protocol == 0)
		protocol = ETH_P_ALL;

	return htons(protocol);
}

static int
pcap_can_set_rfmon_linux(pcap_t *handle)
{
#ifdef HAVE_LIBNL
	char phydev_path[PATH_MAX+1];
	int ret;
#endif

	if (strcmp(handle->opt.device, "any") == 0) {
		/*
		 * Monitor mode makes no sense on the "any" device.
		 */
		return 0;
	}

#ifdef HAVE_LIBNL
	/*
	 * Bleah.  There doesn't seem to be a way to ask a mac80211
	 * device, through libnl, whether it supports monitor mode;
	 * we'll just check whether the device appears to be a
	 * mac80211 device and, if so, assume the device supports
	 * monitor mode.
	 */
	ret = get_mac80211_phydev(handle, handle->opt.device, phydev_path,
	    PATH_MAX);
	if (ret < 0)
		return ret;	/* error */
	if (ret == 1)
		return 1;	/* mac80211 device */
#endif

	return 0;
}

/*
 * Grabs the number of missed packets by the interface from
 * /sys/class/net/{if_name}/statistics/rx_{missed,fifo}_errors.
 *
 * Compared to /proc/net/dev this avoids counting software drops,
 * but may be unimplemented and just return 0.
 * The author has found no straightforward way to check for support.
 */
static long long int
linux_get_stat(const char * if_name, const char * stat) {
	ssize_t bytes_read;
	int fd;
	char buffer[PATH_MAX];

	snprintf(buffer, sizeof(buffer), "/sys/class/net/%s/statistics/%s", if_name, stat);
	fd = open(buffer, O_RDONLY);
	if (fd == -1)
		return 0;

	bytes_read = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (bytes_read == -1)
		return 0;
	buffer[bytes_read] = '\0';

	return strtoll(buffer, NULL, 10);
}

static long long int
linux_if_drops(const char * if_name)
{
	long long int missed = linux_get_stat(if_name, "rx_missed_errors");
	long long int fifo = linux_get_stat(if_name, "rx_fifo_errors");
	return missed + fifo;
}


/*
 * Monitor mode is kind of interesting because we have to reset the
 * interface before exiting. The problem can't really be solved without
 * some daemon taking care of managing usage counts.  If we put the
 * interface into monitor mode, we set a flag indicating that we must
 * take it out of that mode when the interface is closed, and, when
 * closing the interface, if that flag is set we take it out of monitor
 * mode.
 */

static void	pcap_cleanup_linux( pcap_t *handle )
{
	struct pcap_linux *handlep = handle->priv;
#ifdef HAVE_LIBNL
	struct nl80211_state nlstate;
	int ret;
#endif /* HAVE_LIBNL */

	if (handlep->must_do_on_close != 0) {
		/*
		 * There's something we have to do when closing this
		 * pcap_t.
		 */
#ifdef HAVE_LIBNL
		if (handlep->must_do_on_close & MUST_DELETE_MONIF) {
			ret = nl80211_init(handle, &nlstate, handlep->device);
			if (ret >= 0) {
				ret = del_mon_if(handle, handle->fd, &nlstate,
				    handlep->device, handlep->mondevice);
				nl80211_cleanup(&nlstate);
			}
			if (ret < 0) {
				fprintf(stderr,
				    "Can't delete monitor interface %s (%s).\n"
				    "Please delete manually.\n",
				    handlep->mondevice, handle->errbuf);
			}
		}
#endif /* HAVE_LIBNL */

		/*
		 * Take this pcap out of the list of pcaps for which we
		 * have to take the interface out of some mode.
		 */
		pcapint_remove_from_pcaps_to_close(handle);
	}

	if (handle->fd != -1) {
		/*
		 * Destroy the ring buffer (assuming we've set it up),
		 * and unmap it if it's mapped.
		 */
		destroy_ring(handle);
	}

	if (handlep->oneshot_buffer != NULL) {
		free(handlep->oneshot_buffer);
		handlep->oneshot_buffer = NULL;
	}

	if (handlep->mondevice != NULL) {
		free(handlep->mondevice);
		handlep->mondevice = NULL;
	}
	if (handlep->device != NULL) {
		free(handlep->device);
		handlep->device = NULL;
	}

	if (handlep->poll_breakloop_fd != -1) {
		close(handlep->poll_breakloop_fd);
		handlep->poll_breakloop_fd = -1;
	}
	pcapint_cleanup_live_common(handle);
}

#ifdef HAVE_TPACKET3
/*
 * Some versions of TPACKET_V3 have annoying bugs/misfeatures
 * around which we have to work.  Determine if we have those
 * problems or not.
 * 3.19 is the first release with a fixed version of
 * TPACKET_V3.  We treat anything before that as
 * not having a fixed version; that may really mean
 * it has *no* version.
 */
static int has_broken_tpacket_v3(void)
{
	struct utsname utsname;
	const char *release;
	long major, minor;
	int matches, verlen;

	/* No version information, assume broken. */
	if (uname(&utsname) == -1)
		return 1;
	release = utsname.release;

	/* A malformed version, ditto. */
	matches = sscanf(release, "%ld.%ld%n", &major, &minor, &verlen);
	if (matches != 2)
		return 1;
	if (release[verlen] != '.' && release[verlen] != '\0')
		return 1;

	/* OK, a fixed version. */
	if (major > 3 || (major == 3 && minor >= 19))
		return 0;

	/* Too old :( */
	return 1;
}
#endif

/*
 * Set the timeout to be used in poll() with memory-mapped packet capture.
 */
static void
set_poll_timeout(struct pcap_linux *handlep)
{
#ifdef HAVE_TPACKET3
	int broken_tpacket_v3 = has_broken_tpacket_v3();
#endif
	if (handlep->timeout == 0) {
#ifdef HAVE_TPACKET3
		/*
		 * XXX - due to a set of (mis)features in the TPACKET_V3
		 * kernel code prior to the 3.19 kernel, blocking forever
		 * with a TPACKET_V3 socket can, if few packets are
		 * arriving and passing the socket filter, cause most
		 * packets to be dropped.  See libpcap issue #335 for the
		 * full painful story.
		 *
		 * The workaround is to have poll() time out very quickly,
		 * so we grab the frames handed to us, and return them to
		 * the kernel, ASAP.
		 */
		if (handlep->tp_version == TPACKET_V3 && broken_tpacket_v3)
			handlep->poll_timeout = 1;	/* don't block for very long */
		else
#endif
			handlep->poll_timeout = -1;	/* block forever */
	} else if (handlep->timeout > 0) {
#ifdef HAVE_TPACKET3
		/*
		 * For TPACKET_V3, the timeout is handled by the kernel,
		 * so block forever; that way, we don't get extra timeouts.
		 * Don't do that if we have a broken TPACKET_V3, though.
		 */
		if (handlep->tp_version == TPACKET_V3 && !broken_tpacket_v3)
			handlep->poll_timeout = -1;	/* block forever, let TPACKET_V3 wake us up */
		else
#endif
			handlep->poll_timeout = handlep->timeout;	/* block for that amount of time */
	} else {
		/*
		 * Non-blocking mode; we call poll() to pick up error
		 * indications, but we don't want it to wait for
		 * anything.
		 */
		handlep->poll_timeout = 0;
	}
}

static void pcap_breakloop_linux(pcap_t *handle)
{
	pcapint_breakloop_common(handle);
	struct pcap_linux *handlep = handle->priv;

	uint64_t value = 1;

	if (handlep->poll_breakloop_fd != -1) {
		/*
		 * XXX - pcap_breakloop() doesn't have a return value,
		 * so we can't indicate an error.
		 */
DIAG_OFF_WARN_UNUSED_RESULT
		(void)write(handlep->poll_breakloop_fd, &value, sizeof(value));
DIAG_ON_WARN_UNUSED_RESULT
	}
}

/*
 * Set the offset at which to insert VLAN tags.
 * That should be the offset of the type field.
 */
static void
set_vlan_offset(pcap_t *handle)
{
	struct pcap_linux *handlep = handle->priv;

	switch (handle->linktype) {

	case DLT_EN10MB:
		/*
		 * The type field is after the destination and source
		 * MAC address.
		 */
		handlep->vlan_offset = 2 * ETH_ALEN;
		break;

	case DLT_LINUX_SLL:
		/*
		 * The type field is in the last 2 bytes of the
		 * DLT_LINUX_SLL header.
		 */
		handlep->vlan_offset = SLL_HDR_LEN - 2;
		break;

	default:
		handlep->vlan_offset = -1; /* unknown */
		break;
	}
}

/*
 *  Get a handle for a live capture from the given device. You can
 *  pass NULL as device to get all packages (without link level
 *  information of course). If you pass 1 as promisc the interface
 *  will be set to promiscuous mode (XXX: I think this usage should
 *  be deprecated and functions be added to select that later allow
 *  modification of that values -- Torsten).
 */
static int
pcap_activate_linux(pcap_t *handle)
{
	struct pcap_linux *handlep = handle->priv;
	const char	*device;
	int		is_any_device;
	struct ifreq	ifr;
	int		status;
	int		ret;

	device = handle->opt.device;

	/*
	 * Start out assuming no warnings.
	 */
	status = 0;

	/*
	 * Make sure the name we were handed will fit into the ioctls we
	 * might perform on the device; if not, return a "No such device"
	 * indication, as the Linux kernel shouldn't support creating
	 * a device whose name won't fit into those ioctls.
	 *
	 * "Will fit" means "will fit, complete with a null terminator",
	 * so if the length, which does *not* include the null terminator,
	 * is greater than *or equal to* the size of the field into which
	 * we'll be copying it, that won't fit.
	 */
	if (strlen(device) >= sizeof(ifr.ifr_name)) {
		/*
		 * There's nothing more to say, so clear the error
		 * message.
		 */
		handle->errbuf[0] = '\0';
		status = PCAP_ERROR_NO_SUCH_DEVICE;
		goto fail;
	}

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

	handlep->device	= strdup(device);
	if (handlep->device == NULL) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "strdup");
		status = PCAP_ERROR;
		goto fail;
	}

	/*
	 * The "any" device is a special device which causes us not
	 * to bind to a particular device and thus to look at all
	 * devices.
	 */
	is_any_device = (strcmp(device, "any") == 0);
	if (is_any_device) {
		if (handle->opt.promisc) {
			handle->opt.promisc = 0;
			/* Just a warning. */
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "Promiscuous mode not supported on the \"any\" device");
			status = PCAP_WARNING_PROMISC_NOTSUP;
		}
	}

	/* copy timeout value */
	handlep->timeout = handle->opt.timeout;

	/*
	 * If we're in promiscuous mode, then we probably want
	 * to see when the interface drops packets too, so get an
	 * initial count from
	 * /sys/class/net/{if_name}/statistics/rx_{missed,fifo}_errors
	 */
	if (handle->opt.promisc)
		handlep->sysfs_dropped = linux_if_drops(handlep->device);

	/*
	 * If the "any" device is specified, try to open a SOCK_DGRAM.
	 * Otherwise, open a SOCK_RAW.
	 */
	ret = setup_socket(handle, is_any_device);
	if (ret < 0) {
		/*
		 * Fatal error; the return value is the error code,
		 * and handle->errbuf has been set to an appropriate
		 * error message.
		 */
		status = ret;
		goto fail;
	}
	if (ret > 0) {
		/*
		 * We got a warning; return that, as handle->errbuf
		 * might have been overwritten by this warning.
		 */
		status = ret;
	}

	/*
	 * Success (possibly with a warning).
	 *
	 * First, try to allocate an event FD for breakloop, if
	 * we're not going to start in non-blocking mode.
	 */
	if (!handle->opt.nonblock) {
		handlep->poll_breakloop_fd = eventfd(0, EFD_NONBLOCK);
		if (handlep->poll_breakloop_fd == -1) {
			/*
			 * Failed.
			 */
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno, "could not open eventfd");
			status = PCAP_ERROR;
			goto fail;
		}
	}

	/*
	 * Succeeded.
	 * Try to set up memory-mapped access.
	 */
	ret = setup_mmapped(handle);
	if (ret < 0) {
		/*
		 * We failed to set up to use it, or the
		 * kernel supports it, but we failed to
		 * enable it.  The return value is the
		 * error status to return and, if it's
		 * PCAP_ERROR, handle->errbuf contains
		 * the error message.
		 */
		status = ret;
		goto fail;
	}
	if (ret > 0) {
		/*
		 * We got a warning; return that, as handle->errbuf
		 * might have been overwritten by this warning.
		 */
		status = ret;
	}

	/*
	 * We succeeded.  status has been set to the status to return,
	 * which might be 0, or might be a PCAP_WARNING_ value.
	 */
	/*
	 * Now that we have activated the mmap ring, we can
	 * set the correct protocol.
	 */
	if ((ret = iface_bind(handle->fd, handlep->ifindex,
	    handle->errbuf, pcap_protocol(handle))) != 0) {
		status = ret;
		goto fail;
	}

	handle->inject_op = pcap_inject_linux;
	handle->setfilter_op = pcap_setfilter_linux;
	handle->setdirection_op = pcap_setdirection_linux;
	handle->set_datalink_op = pcap_set_datalink_linux;
	handle->setnonblock_op = pcap_setnonblock_linux;
	handle->getnonblock_op = pcap_getnonblock_linux;
	handle->cleanup_op = pcap_cleanup_linux;
	handle->stats_op = pcap_stats_linux;
	handle->breakloop_op = pcap_breakloop_linux;

	switch (handlep->tp_version) {

	case TPACKET_V2:
		handle->read_op = pcap_read_linux_mmap_v2;
		break;
#ifdef HAVE_TPACKET3
	case TPACKET_V3:
		handle->read_op = pcap_read_linux_mmap_v3;
		break;
#endif
	}
	handle->oneshot_callback = pcapint_oneshot_linux;
	handle->selectable_fd = handle->fd;

	return status;

fail:
	pcap_cleanup_linux(handle);
	return status;
}

static int
pcap_set_datalink_linux(pcap_t *handle, int dlt)
{
	handle->linktype = dlt;

	/*
	 * Update the offset at which to insert VLAN tags for the
	 * new link-layer type.
	 */
	set_vlan_offset(handle);

	return 0;
}

/*
 * linux_check_direction()
 *
 * Do checks based on packet direction.
 */
static inline int
linux_check_direction(const pcap_t *handle, const struct sockaddr_ll *sll)
{
	struct pcap_linux	*handlep = handle->priv;

	if (sll->sll_pkttype == PACKET_OUTGOING) {
		/*
		 * Outgoing packet.
		 * If this is from the loopback device, reject it;
		 * we'll see the packet as an incoming packet as well,
		 * and we don't want to see it twice.
		 */
		if (sll->sll_ifindex == handlep->lo_ifindex)
			return 0;

		/*
		 * If this is an outgoing CAN or CAN FD frame, and
		 * the user doesn't only want outgoing packets,
		 * reject it; CAN devices and drivers, and the CAN
		 * stack, always arrange to loop back transmitted
		 * packets, so they also appear as incoming packets.
		 * We don't want duplicate packets, and we can't
		 * easily distinguish packets looped back by the CAN
		 * layer than those received by the CAN layer, so we
		 * eliminate this packet instead.
		 *
		 * We check whether this is a CAN or CAN FD frame
		 * by checking whether the device's hardware type
		 * is ARPHRD_CAN.
		 */
		if (sll->sll_hatype == ARPHRD_CAN &&
		     handle->direction != PCAP_D_OUT)
			return 0;

		/*
		 * If the user only wants incoming packets, reject it.
		 */
		if (handle->direction == PCAP_D_IN)
			return 0;
	} else {
		/*
		 * Incoming packet.
		 * If the user only wants outgoing packets, reject it.
		 */
		if (handle->direction == PCAP_D_OUT)
			return 0;
	}
	return 1;
}

/*
 * Check whether the device to which the pcap_t is bound still exists.
 * We do so by asking what address the socket is bound to, and checking
 * whether the ifindex in the address is -1, meaning "that device is gone",
 * or some other value, meaning "that device still exists".
 */
static int
device_still_exists(pcap_t *handle)
{
	struct pcap_linux *handlep = handle->priv;
	struct sockaddr_ll addr;
	socklen_t addr_len;

	/*
	 * If handlep->ifindex is -1, the socket isn't bound, meaning
	 * we're capturing on the "any" device; that device never
	 * disappears.  (It should also never be configured down, so
	 * we shouldn't even get here, but let's make sure.)
	 */
	if (handlep->ifindex == -1)
		return (1);	/* it's still here */

	/*
	 * OK, now try to get the address for the socket.
	 */
	addr_len = sizeof (addr);
	if (getsockname(handle->fd, (struct sockaddr *) &addr, &addr_len) == -1) {
		/*
		 * Error - report an error and return -1.
		 */
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "getsockname failed");
		return (-1);
	}
	if (addr.sll_ifindex == -1) {
		/*
		 * This means the device went away.
		 */
		return (0);
	}

	/*
	 * The device presumably just went down.
	 */
	return (1);
}

static int
pcap_inject_linux(pcap_t *handle, const void *buf, int size)
{
	struct pcap_linux *handlep = handle->priv;
	int ret;

	if (handlep->ifindex == -1) {
		/*
		 * We don't support sending on the "any" device.
		 */
		pcapint_strlcpy(handle->errbuf,
		    "Sending packets isn't supported on the \"any\" device",
		    PCAP_ERRBUF_SIZE);
		return (-1);
	}

	if (handlep->cooked) {
		/*
		 * We don't support sending on cooked-mode sockets.
		 *
		 * XXX - how do you send on a bound cooked-mode
		 * socket?
		 * Is a "sendto()" required there?
		 */
		pcapint_strlcpy(handle->errbuf,
		    "Sending packets isn't supported in cooked mode",
		    PCAP_ERRBUF_SIZE);
		return (-1);
	}

	ret = (int)send(handle->fd, buf, size, 0);
	if (ret == -1) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "send");
		return (-1);
	}
	return (ret);
}

/*
 *  Get the statistics for the given packet capture handle.
 */
static int
pcap_stats_linux(pcap_t *handle, struct pcap_stat *stats)
{
	struct pcap_linux *handlep = handle->priv;
#ifdef HAVE_TPACKET3
	/*
	 * For sockets using TPACKET_V2, the extra stuff at the end
	 * of a struct tpacket_stats_v3 will not be filled in, and
	 * we don't look at it so this is OK even for those sockets.
	 * In addition, the PF_PACKET socket code in the kernel only
	 * uses the length parameter to compute how much data to
	 * copy out and to indicate how much data was copied out, so
	 * it's OK to base it on the size of a struct tpacket_stats.
	 *
	 * XXX - it's probably OK, in fact, to just use a
	 * struct tpacket_stats for V3 sockets, as we don't
	 * care about the tp_freeze_q_cnt stat.
	 */
	struct tpacket_stats_v3 kstats;
#else /* HAVE_TPACKET3 */
	struct tpacket_stats kstats;
#endif /* HAVE_TPACKET3 */
	socklen_t len = sizeof (struct tpacket_stats);

	long long if_dropped = 0;

	/*
	 * To fill in ps_ifdrop, we parse
	 * /sys/class/net/{if_name}/statistics/rx_{missed,fifo}_errors
	 * for the numbers
	 */
	if (handle->opt.promisc)
	{
		/*
		 * XXX - is there any reason to do this by remembering
		 * the last counts value, subtracting it from the
		 * current counts value, and adding that to stat.ps_ifdrop,
		 * maintaining stat.ps_ifdrop as a count, rather than just
		 * saving the *initial* counts value and setting
		 * stat.ps_ifdrop to the difference between the current
		 * value and the initial value?
		 *
		 * One reason might be to handle the count wrapping
		 * around, on platforms where the count is 32 bits
		 * and where you might get more than 2^32 dropped
		 * packets; is there any other reason?
		 *
		 * (We maintain the count as a long long int so that,
		 * if the kernel maintains the counts as 64-bit even
		 * on 32-bit platforms, we can handle the real count.
		 *
		 * Unfortunately, we can't report 64-bit counts; we
		 * need a better API for reporting statistics, such as
		 * one that reports them in a style similar to the
		 * pcapng Interface Statistics Block, so that 1) the
		 * counts are 64-bit, 2) it's easier to add new statistics
		 * without breaking the ABI, and 3) it's easier to
		 * indicate to a caller that wants one particular
		 * statistic that it's not available by just not supplying
		 * it.)
		 */
		if_dropped = handlep->sysfs_dropped;
		handlep->sysfs_dropped = linux_if_drops(handlep->device);
		handlep->stat.ps_ifdrop += (u_int)(handlep->sysfs_dropped - if_dropped);
	}

	/*
	 * Try to get the packet counts from the kernel.
	 */
	if (getsockopt(handle->fd, SOL_PACKET, PACKET_STATISTICS,
			&kstats, &len) > -1) {
		/*
		 * "ps_recv" counts only packets that *passed* the
		 * filter, not packets that didn't pass the filter.
		 * This includes packets later dropped because we
		 * ran out of buffer space.
		 *
		 * "ps_drop" counts packets dropped because we ran
		 * out of buffer space.  It doesn't count packets
		 * dropped by the interface driver.  It counts only
		 * packets that passed the filter.
		 *
		 * See above for ps_ifdrop.
		 *
		 * Both statistics include packets not yet read from
		 * the kernel by libpcap, and thus not yet seen by
		 * the application.
		 *
		 * In "linux/net/packet/af_packet.c", at least in 2.6.27
		 * through 5.6 kernels, "tp_packets" is incremented for
		 * every packet that passes the packet filter *and* is
		 * successfully copied to the ring buffer; "tp_drops" is
		 * incremented for every packet dropped because there's
		 * not enough free space in the ring buffer.
		 *
		 * When the statistics are returned for a PACKET_STATISTICS
		 * "getsockopt()" call, "tp_drops" is added to "tp_packets",
		 * so that "tp_packets" counts all packets handed to
		 * the PF_PACKET socket, including packets dropped because
		 * there wasn't room on the socket buffer - but not
		 * including packets that didn't pass the filter.
		 *
		 * In the BSD BPF, the count of received packets is
		 * incremented for every packet handed to BPF, regardless
		 * of whether it passed the filter.
		 *
		 * We can't make "pcap_stats()" work the same on both
		 * platforms, but the best approximation is to return
		 * "tp_packets" as the count of packets and "tp_drops"
		 * as the count of drops.
		 *
		 * Keep a running total because each call to
		 *    getsockopt(handle->fd, SOL_PACKET, PACKET_STATISTICS, ....
		 * resets the counters to zero.
		 */
		handlep->stat.ps_recv += kstats.tp_packets;
		handlep->stat.ps_drop += kstats.tp_drops;
		*stats = handlep->stat;
		return 0;
	}

	pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE, errno,
	    "failed to get statistics from socket");
	return -1;
}

/*
 * A PF_PACKET socket can be bound to any network interface.
 */
static int
can_be_bound(const char *name _U_)
{
	return (1);
}

/*
 * Get a socket to use with various interface ioctls.
 */
static int
get_if_ioctl_socket(void)
{
	int fd;

	/*
	 * This is a bit ugly.
	 *
	 * There isn't a socket type that's guaranteed to work.
	 *
	 * AF_NETLINK will work *if* you have Netlink configured into the
	 * kernel (can it be configured out if you have any networking
	 * support at all?) *and* if you're running a sufficiently recent
	 * kernel, but not all the kernels we support are sufficiently
	 * recent - that feature was introduced in Linux 4.6.
	 *
	 * AF_UNIX will work *if* you have UNIX-domain sockets configured
	 * into the kernel and *if* you're not on a system that doesn't
	 * allow them - some SELinux systems don't allow you create them.
	 * Most systems probably have them configured in, but not all systems
	 * have them configured in and allow them to be created.
	 *
	 * AF_INET will work *if* you have IPv4 configured into the kernel,
	 * but, apparently, some systems have network adapters but have
	 * kernels without IPv4 support.
	 *
	 * AF_INET6 will work *if* you have IPv6 configured into the
	 * kernel, but if you don't have AF_INET, you might not have
	 * AF_INET6, either (that is, independently on its own grounds).
	 *
	 * AF_PACKET would work, except that some of these calls should
	 * work even if you *don't* have capture permission (you should be
	 * able to enumerate interfaces and get information about them
	 * without capture permission; you shouldn't get a failure until
	 * you try pcap_activate()).  (If you don't allow programs to
	 * get as much information as possible about interfaces if you
	 * don't have permission to capture, you run the risk of users
	 * asking "why isn't it showing XXX" - or, worse, if you don't
	 * show interfaces *at all* if you don't have permission to
	 * capture on them, "why do no interfaces show up?" - when the
	 * real problem is a permissions problem.  Error reports of that
	 * type require a lot more back-and-forth to debug, as evidenced
	 * by many Wireshark bugs/mailing list questions/Q&A questions.)
	 *
	 * So:
	 *
	 * we first try an AF_NETLINK socket, where "try" includes
	 * "try to do a device ioctl on it", as, in the future, once
	 * pre-4.6 kernels are sufficiently rare, that will probably
	 * be the mechanism most likely to work;
	 *
	 * if that fails, we try an AF_UNIX socket, as that's less
	 * likely to be configured out on a networking-capable system
	 * than is IP;
	 *
	 * if that fails, we try an AF_INET6 socket;
	 *
	 * if that fails, we try an AF_INET socket.
	 */
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd != -1) {
		/*
		 * OK, let's make sure we can do an SIOCGIFNAME
		 * ioctl.
		 */
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		if (ioctl(fd, SIOCGIFNAME, &ifr) == 0 ||
		    errno != EOPNOTSUPP) {
			/*
			 * It succeeded, or failed for some reason
			 * other than "netlink sockets don't support
			 * device ioctls".  Go with the AF_NETLINK
			 * socket.
			 */
			return (fd);
		}

		/*
		 * OK, that didn't work, so it's as bad as "netlink
		 * sockets aren't available".  Close the socket and
		 * drive on.
		 */
		close(fd);
	}

	/*
	 * Now try an AF_UNIX socket.
	 */
	fd = socket(AF_UNIX, SOCK_RAW, 0);
	if (fd != -1) {
		/*
		 * OK, we got it!
		 */
		return (fd);
	}

	/*
	 * Now try an AF_INET6 socket.
	 */
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd != -1) {
		return (fd);
	}

	/*
	 * Now try an AF_INET socket.
	 *
	 * XXX - if that fails, is there anything else we should try?
	 * AF_CAN, for embedded systems in vehicles, in case they're
	 * built without Internet protocol support?  Any other socket
	 * types popular in non-Internet embedded systems?
	 */
	return (socket(AF_INET, SOCK_DGRAM, 0));
}

/*
 * Get additional flags for a device, using SIOCGIFMEDIA.
 */
static int
get_if_flags(const char *name, bpf_u_int32 *flags, char *errbuf)
{
	int sock;
	FILE *fh;
	unsigned int arptype;
	struct ifreq ifr;
	struct ethtool_value info;

	if (*flags & PCAP_IF_LOOPBACK) {
		/*
		 * Loopback devices aren't wireless, and "connected"/
		 * "disconnected" doesn't apply to them.
		 */
		*flags |= PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE;
		return 0;
	}

	sock = get_if_ioctl_socket();
	if (sock == -1) {
		pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE, errno,
		    "Can't create socket to get ethtool information for %s",
		    name);
		return -1;
	}

	/*
	 * OK, what type of network is this?
	 * In particular, is it wired or wireless?
	 */
	if (is_wifi(name)) {
		/*
		 * Wi-Fi, hence wireless.
		 */
		*flags |= PCAP_IF_WIRELESS;
	} else {
		/*
		 * OK, what does /sys/class/net/{if_name}/type contain?
		 * (We don't use that for Wi-Fi, as it'll report
		 * "Ethernet", i.e. ARPHRD_ETHER, for non-monitor-
		 * mode devices.)
		 */
		char *pathstr;

		if (asprintf(&pathstr, "/sys/class/net/%s/type", name) == -1) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			    "%s: Can't generate path name string for /sys/class/net device",
			    name);
			close(sock);
			return -1;
		}
		fh = fopen(pathstr, "r");
		if (fh != NULL) {
			if (fscanf(fh, "%u", &arptype) == 1) {
				/*
				 * OK, we got an ARPHRD_ type; what is it?
				 */
				switch (arptype) {

				case ARPHRD_LOOPBACK:
					/*
					 * These are types to which
					 * "connected" and "disconnected"
					 * don't apply, so don't bother
					 * asking about it.
					 *
					 * XXX - add other types?
					 */
					close(sock);
					fclose(fh);
					free(pathstr);
					return 0;

				case ARPHRD_IRDA:
				case ARPHRD_IEEE80211:
				case ARPHRD_IEEE80211_PRISM:
				case ARPHRD_IEEE80211_RADIOTAP:
#ifdef ARPHRD_IEEE802154
				case ARPHRD_IEEE802154:
#endif
#ifdef ARPHRD_IEEE802154_MONITOR
				case ARPHRD_IEEE802154_MONITOR:
#endif
#ifdef ARPHRD_6LOWPAN
				case ARPHRD_6LOWPAN:
#endif
					/*
					 * Various wireless types.
					 */
					*flags |= PCAP_IF_WIRELESS;
					break;
				}
			}
			fclose(fh);
		}
		free(pathstr);
	}

#ifdef ETHTOOL_GLINK
	memset(&ifr, 0, sizeof(ifr));
	pcapint_strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	info.cmd = ETHTOOL_GLINK;
	/*
	 * XXX - while Valgrind handles SIOCETHTOOL and knows that
	 * the ETHTOOL_GLINK command sets the .data member of the
	 * structure, Memory Sanitizer doesn't yet do so:
	 *
	 *    https://bugs.llvm.org/show_bug.cgi?id=45814
	 *
	 * For now, we zero it out to squelch warnings; if the bug
	 * in question is fixed, we can remove this.
	 */
	info.data = 0;
	ifr.ifr_data = (caddr_t)&info;
	if (ioctl(sock, SIOCETHTOOL, &ifr) == -1) {
		int save_errno = errno;

		switch (save_errno) {

		case EOPNOTSUPP:
		case EINVAL:
			/*
			 * OK, this OS version or driver doesn't support
			 * asking for this information.
			 * XXX - distinguish between "this doesn't
			 * support ethtool at all because it's not
			 * that type of device" vs. "this doesn't
			 * support ethtool even though it's that
			 * type of device", and return "unknown".
			 */
			*flags |= PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE;
			close(sock);
			return 0;

		case ENODEV:
			/*
			 * OK, no such device.
			 * The user will find that out when they try to
			 * activate the device; just say "OK" and
			 * don't set anything.
			 */
			close(sock);
			return 0;

		default:
			/*
			 * Other error.
			 */
			pcapint_fmt_errmsg_for_errno(errbuf, PCAP_ERRBUF_SIZE,
			    save_errno,
			    "%s: SIOCETHTOOL(ETHTOOL_GLINK) ioctl failed",
			    name);
			close(sock);
			return -1;
		}
	}

	/*
	 * Is it connected?
	 */
	if (info.data) {
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
#endif

	close(sock);
	return 0;
}

int
pcapint_platform_finddevs(pcap_if_list_t *devlistp, char *errbuf)
{
	/*
	 * Get the list of regular interfaces first.
	 */
	if (pcapint_findalldevs_interfaces(devlistp, errbuf, can_be_bound,
	    get_if_flags) == -1)
		return (-1);	/* failure */

	/*
	 * Add the "any" device.
	 */
	if (pcap_add_any_dev(devlistp, errbuf) == NULL)
		return (-1);

	return (0);
}

/*
 * Set direction flag: Which packets do we accept on a forwarding
 * single device? IN, OUT or both?
 */
static int
pcap_setdirection_linux(pcap_t *handle, pcap_direction_t d)
{
	/*
	 * It's guaranteed, at this point, that d is a valid
	 * direction value.
	 */
	handle->direction = d;
	return 0;
}

static int
is_wifi(const char *device)
{
	char *pathstr;
	struct stat statb;

	/*
	 * See if there's a sysfs wireless directory for it.
	 * If so, it's a wireless interface.
	 */
	if (asprintf(&pathstr, "/sys/class/net/%s/wireless", device) == -1) {
		/*
		 * Just give up here.
		 */
		return 0;
	}
	if (stat(pathstr, &statb) == 0) {
		free(pathstr);
		return 1;
	}
	free(pathstr);

	return 0;
}

/*
 *  Linux uses the ARP hardware type to identify the type of an
 *  interface. pcap uses the DLT_xxx constants for this. This
 *  function takes a pointer to a "pcap_t", and an ARPHRD_xxx
 *  constant, as arguments, and sets "handle->linktype" to the
 *  appropriate DLT_XXX constant and sets "handle->offset" to
 *  the appropriate value (to make "handle->offset" plus link-layer
 *  header length be a multiple of 4, so that the link-layer payload
 *  will be aligned on a 4-byte boundary when capturing packets).
 *  (If the offset isn't set here, it'll be 0; add code as appropriate
 *  for cases where it shouldn't be 0.)
 *
 *  If "cooked_ok" is non-zero, we can use DLT_LINUX_SLL and capture
 *  in cooked mode; otherwise, we can't use cooked mode, so we have
 *  to pick some type that works in raw mode, or fail.
 *
 *  Sets the link type to -1 if unable to map the type.
 *
 *  Returns 0 on success or a PCAP_ERROR_ value on error.
 */
static int map_arphrd_to_dlt(pcap_t *handle, int arptype,
			     const char *device, int cooked_ok)
{
	static const char cdma_rmnet[] = "cdma_rmnet";

	switch (arptype) {

	case ARPHRD_ETHER:
		/*
		 * For various annoying reasons having to do with DHCP
		 * software, some versions of Android give the mobile-
		 * phone-network interface an ARPHRD_ value of
		 * ARPHRD_ETHER, even though the packets supplied by
		 * that interface have no link-layer header, and begin
		 * with an IP header, so that the ARPHRD_ value should
		 * be ARPHRD_NONE.
		 *
		 * Detect those devices by checking the device name, and
		 * use DLT_RAW for them.
		 */
		if (strncmp(device, cdma_rmnet, sizeof cdma_rmnet - 1) == 0) {
			handle->linktype = DLT_RAW;
			return 0;
		}

		/*
		 * Is this a real Ethernet device?  If so, give it a
		 * link-layer-type list with DLT_EN10MB and DLT_DOCSIS, so
		 * that an application can let you choose it, in case you're
		 * capturing DOCSIS traffic that a Cisco Cable Modem
		 * Termination System is putting out onto an Ethernet (it
		 * doesn't put an Ethernet header onto the wire, it puts raw
		 * DOCSIS frames out on the wire inside the low-level
		 * Ethernet framing).
		 *
		 * XXX - are there any other sorts of "fake Ethernet" that
		 * have ARPHRD_ETHER but that shouldn't offer DLT_DOCSIS as
		 * a Cisco CMTS won't put traffic onto it or get traffic
		 * bridged onto it?  ISDN is handled in "setup_socket()",
		 * as we fall back on cooked mode there, and we use
		 * is_wifi() to check for 802.11 devices; are there any
		 * others?
		 */
		if (!is_wifi(device)) {
			int ret;

			/*
			 * This is not a Wi-Fi device but it could be
			 * a DSA master/management network device.
			 */
			ret = iface_dsa_get_proto_info(device, handle);
			if (ret < 0)
				return ret;

			if (ret == 1) {
				/*
				 * This is a DSA master/management network
				 * device linktype is already set by
				 * iface_dsa_get_proto_info() set an
				 * appropriate offset here.
				 */
				handle->offset = 2;
				break;
			}

			/*
			 * It's not a Wi-Fi device; offer DOCSIS.
			 */
			handle->dlt_list = (u_int *) malloc(sizeof(u_int) * 2);
			if (handle->dlt_list == NULL) {
				pcapint_fmt_errmsg_for_errno(handle->errbuf,
				    PCAP_ERRBUF_SIZE, errno, "malloc");
				return (PCAP_ERROR);
			}
			handle->dlt_list[0] = DLT_EN10MB;
			handle->dlt_list[1] = DLT_DOCSIS;
			handle->dlt_count = 2;
		}
		/* FALLTHROUGH */

	case ARPHRD_METRICOM:
	case ARPHRD_LOOPBACK:
		handle->linktype = DLT_EN10MB;
		handle->offset = 2;
		break;

	case ARPHRD_EETHER:
		handle->linktype = DLT_EN3MB;
		break;

	case ARPHRD_AX25:
		handle->linktype = DLT_AX25_KISS;
		break;

	case ARPHRD_PRONET:
		handle->linktype = DLT_PRONET;
		break;

	case ARPHRD_CHAOS:
		handle->linktype = DLT_CHAOS;
		break;
#ifndef ARPHRD_CAN
#define ARPHRD_CAN 280
#endif
	case ARPHRD_CAN:
		handle->linktype = DLT_CAN_SOCKETCAN;
		break;

#ifndef ARPHRD_IEEE802_TR
#define ARPHRD_IEEE802_TR 800	/* From Linux 2.4 */
#endif
	case ARPHRD_IEEE802_TR:
	case ARPHRD_IEEE802:
		handle->linktype = DLT_IEEE802;
		handle->offset = 2;
		break;

	case ARPHRD_ARCNET:
		handle->linktype = DLT_ARCNET_LINUX;
		break;

#ifndef ARPHRD_FDDI	/* From Linux 2.2.13 */
#define ARPHRD_FDDI	774
#endif
	case ARPHRD_FDDI:
		handle->linktype = DLT_FDDI;
		handle->offset = 3;
		break;

#ifndef ARPHRD_ATM  /* FIXME: How to #include this? */
#define ARPHRD_ATM 19
#endif
	case ARPHRD_ATM:
		/*
		 * The Classical IP implementation in ATM for Linux
		 * supports both what RFC 1483 calls "LLC Encapsulation",
		 * in which each packet has an LLC header, possibly
		 * with a SNAP header as well, prepended to it, and
		 * what RFC 1483 calls "VC Based Multiplexing", in which
		 * different virtual circuits carry different network
		 * layer protocols, and no header is prepended to packets.
		 *
		 * They both have an ARPHRD_ type of ARPHRD_ATM, so
		 * you can't use the ARPHRD_ type to find out whether
		 * captured packets will have an LLC header, and,
		 * while there's a socket ioctl to *set* the encapsulation
		 * type, there's no ioctl to *get* the encapsulation type.
		 *
		 * This means that
		 *
		 *	programs that dissect Linux Classical IP frames
		 *	would have to check for an LLC header and,
		 *	depending on whether they see one or not, dissect
		 *	the frame as LLC-encapsulated or as raw IP (I
		 *	don't know whether there's any traffic other than
		 *	IP that would show up on the socket, or whether
		 *	there's any support for IPv6 in the Linux
		 *	Classical IP code);
		 *
		 *	filter expressions would have to compile into
		 *	code that checks for an LLC header and does
		 *	the right thing.
		 *
		 * Both of those are a nuisance - and, at least on systems
		 * that support PF_PACKET sockets, we don't have to put
		 * up with those nuisances; instead, we can just capture
		 * in cooked mode.  That's what we'll do, if we can.
		 * Otherwise, we'll just fail.
		 */
		if (cooked_ok)
			handle->linktype = DLT_LINUX_SLL;
		else
			handle->linktype = -1;
		break;

#ifndef ARPHRD_IEEE80211  /* From Linux 2.4.6 */
#define ARPHRD_IEEE80211 801
#endif
	case ARPHRD_IEEE80211:
		handle->linktype = DLT_IEEE802_11;
		break;

#ifndef ARPHRD_IEEE80211_PRISM  /* From Linux 2.4.18 */
#define ARPHRD_IEEE80211_PRISM 802
#endif
	case ARPHRD_IEEE80211_PRISM:
		handle->linktype = DLT_PRISM_HEADER;
		break;

#ifndef ARPHRD_IEEE80211_RADIOTAP /* new */
#define ARPHRD_IEEE80211_RADIOTAP 803
#endif
	case ARPHRD_IEEE80211_RADIOTAP:
		handle->linktype = DLT_IEEE802_11_RADIO;
		break;

	case ARPHRD_PPP:
		/*
		 * Some PPP code in the kernel supplies no link-layer
		 * header whatsoever to PF_PACKET sockets; other PPP
		 * code supplies PPP link-layer headers ("syncppp.c");
		 * some PPP code might supply random link-layer
		 * headers (PPP over ISDN - there's code in Ethereal,
		 * for example, to cope with PPP-over-ISDN captures
		 * with which the Ethereal developers have had to cope,
		 * heuristically trying to determine which of the
		 * oddball link-layer headers particular packets have).
		 *
		 * As such, we just punt, and run all PPP interfaces
		 * in cooked mode, if we can; otherwise, we just treat
		 * it as DLT_RAW, for now - if somebody needs to capture,
		 * on a 2.0[.x] kernel, on PPP devices that supply a
		 * link-layer header, they'll have to add code here to
		 * map to the appropriate DLT_ type (possibly adding a
		 * new DLT_ type, if necessary).
		 */
		if (cooked_ok)
			handle->linktype = DLT_LINUX_SLL;
		else {
			/*
			 * XXX - handle ISDN types here?  We can't fall
			 * back on cooked sockets, so we'd have to
			 * figure out from the device name what type of
			 * link-layer encapsulation it's using, and map
			 * that to an appropriate DLT_ value, meaning
			 * we'd map "isdnN" devices to DLT_RAW (they
			 * supply raw IP packets with no link-layer
			 * header) and "isdY" devices to a new DLT_I4L_IP
			 * type that has only an Ethernet packet type as
			 * a link-layer header.
			 *
			 * But sometimes we seem to get random crap
			 * in the link-layer header when capturing on
			 * ISDN devices....
			 */
			handle->linktype = DLT_RAW;
		}
		break;

#ifndef ARPHRD_CISCO
#define ARPHRD_CISCO 513 /* previously ARPHRD_HDLC */
#endif
	case ARPHRD_CISCO:
		handle->linktype = DLT_C_HDLC;
		break;

	/* Not sure if this is correct for all tunnels, but it
	 * works for CIPE */
	case ARPHRD_TUNNEL:
#ifndef ARPHRD_SIT
#define ARPHRD_SIT 776	/* From Linux 2.2.13 */
#endif
	case ARPHRD_SIT:
	case ARPHRD_CSLIP:
	case ARPHRD_SLIP6:
	case ARPHRD_CSLIP6:
	case ARPHRD_ADAPT:
	case ARPHRD_SLIP:
#ifndef ARPHRD_RAWHDLC
#define ARPHRD_RAWHDLC 518
#endif
	case ARPHRD_RAWHDLC:
#ifndef ARPHRD_DLCI
#define ARPHRD_DLCI 15
#endif
	case ARPHRD_DLCI:
		/*
		 * XXX - should some of those be mapped to DLT_LINUX_SLL
		 * instead?  Should we just map all of them to DLT_LINUX_SLL?
		 */
		handle->linktype = DLT_RAW;
		break;

#ifndef ARPHRD_FRAD
#define ARPHRD_FRAD 770
#endif
	case ARPHRD_FRAD:
		handle->linktype = DLT_FRELAY;
		break;

	case ARPHRD_LOCALTLK:
		handle->linktype = DLT_LTALK;
		break;

	case 18:
		/*
		 * RFC 4338 defines an encapsulation for IP and ARP
		 * packets that's compatible with the RFC 2625
		 * encapsulation, but that uses a different ARP
		 * hardware type and hardware addresses.  That
		 * ARP hardware type is 18; Linux doesn't define
		 * any ARPHRD_ value as 18, but if it ever officially
		 * supports RFC 4338-style IP-over-FC, it should define
		 * one.
		 *
		 * For now, we map it to DLT_IP_OVER_FC, in the hopes
		 * that this will encourage its use in the future,
		 * should Linux ever officially support RFC 4338-style
		 * IP-over-FC.
		 */
		handle->linktype = DLT_IP_OVER_FC;
		break;

#ifndef ARPHRD_FCPP
#define ARPHRD_FCPP	784
#endif
	case ARPHRD_FCPP:
#ifndef ARPHRD_FCAL
#define ARPHRD_FCAL	785
#endif
	case ARPHRD_FCAL:
#ifndef ARPHRD_FCPL
#define ARPHRD_FCPL	786
#endif
	case ARPHRD_FCPL:
#ifndef ARPHRD_FCFABRIC
#define ARPHRD_FCFABRIC	787
#endif
	case ARPHRD_FCFABRIC:
		/*
		 * Back in 2002, Donald Lee at Cray wanted a DLT_ for
		 * IP-over-FC:
		 *
		 *	https://www.mail-archive.com/tcpdump-workers@sandelman.ottawa.on.ca/msg01043.html
		 *
		 * and one was assigned.
		 *
		 * In a later private discussion (spun off from a message
		 * on the ethereal-users list) on how to get that DLT_
		 * value in libpcap on Linux, I ended up deciding that
		 * the best thing to do would be to have him tweak the
		 * driver to set the ARPHRD_ value to some ARPHRD_FCxx
		 * type, and map all those types to DLT_IP_OVER_FC:
		 *
		 *	I've checked into the libpcap and tcpdump CVS tree
		 *	support for DLT_IP_OVER_FC.  In order to use that,
		 *	you'd have to modify your modified driver to return
		 *	one of the ARPHRD_FCxxx types, in "fcLINUXfcp.c" -
		 *	change it to set "dev->type" to ARPHRD_FCFABRIC, for
		 *	example (the exact value doesn't matter, it can be
		 *	any of ARPHRD_FCPP, ARPHRD_FCAL, ARPHRD_FCPL, or
		 *	ARPHRD_FCFABRIC).
		 *
		 * 11 years later, Christian Svensson wanted to map
		 * various ARPHRD_ values to DLT_FC_2 and
		 * DLT_FC_2_WITH_FRAME_DELIMS for raw Fibre Channel
		 * frames:
		 *
		 *	https://github.com/mcr/libpcap/pull/29
		 *
		 * There doesn't seem to be any network drivers that uses
		 * any of the ARPHRD_FC* values for IP-over-FC, and
		 * it's not exactly clear what the "Dummy types for non
		 * ARP hardware" are supposed to mean (link-layer
		 * header type?  Physical network type?), so it's
		 * not exactly clear why the ARPHRD_FC* types exist
		 * in the first place.
		 *
		 * For now, we map them to DLT_FC_2, and provide an
		 * option of DLT_FC_2_WITH_FRAME_DELIMS, as well as
		 * DLT_IP_OVER_FC just in case there's some old
		 * driver out there that uses one of those types for
		 * IP-over-FC on which somebody wants to capture
		 * packets.
		 */
		handle->linktype = DLT_FC_2;
		handle->dlt_list = (u_int *) malloc(sizeof(u_int) * 3);
		if (handle->dlt_list == NULL) {
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno, "malloc");
			return (PCAP_ERROR);
		}
		handle->dlt_list[0] = DLT_FC_2;
		handle->dlt_list[1] = DLT_FC_2_WITH_FRAME_DELIMS;
		handle->dlt_list[2] = DLT_IP_OVER_FC;
		handle->dlt_count = 3;
		break;

#ifndef ARPHRD_IRDA
#define ARPHRD_IRDA	783
#endif
	case ARPHRD_IRDA:
		/* Don't expect IP packet out of this interfaces... */
		handle->linktype = DLT_LINUX_IRDA;
		/* We need to save packet direction for IrDA decoding,
		 * so let's use "Linux-cooked" mode. Jean II
		 *
		 * XXX - this is handled in setup_socket(). */
		/* handlep->cooked = 1; */
		break;

	/* ARPHRD_LAPD is unofficial and randomly allocated, if reallocation
	 * is needed, please report it to <daniele@orlandi.com> */
#ifndef ARPHRD_LAPD
#define ARPHRD_LAPD	8445
#endif
	case ARPHRD_LAPD:
		/* Don't expect IP packet out of this interfaces... */
		handle->linktype = DLT_LINUX_LAPD;
		break;

#ifndef ARPHRD_NONE
#define ARPHRD_NONE	0xFFFE
#endif
	case ARPHRD_NONE:
		/*
		 * No link-layer header; packets are just IP
		 * packets, so use DLT_RAW.
		 */
		handle->linktype = DLT_RAW;
		break;

#ifndef ARPHRD_IEEE802154
#define ARPHRD_IEEE802154      804
#endif
       case ARPHRD_IEEE802154:
               handle->linktype =  DLT_IEEE802_15_4_NOFCS;
               break;

#ifndef ARPHRD_NETLINK
#define ARPHRD_NETLINK	824
#endif
	case ARPHRD_NETLINK:
		handle->linktype = DLT_NETLINK;
		/*
		 * We need to use cooked mode, so that in sll_protocol we
		 * pick up the netlink protocol type such as NETLINK_ROUTE,
		 * NETLINK_GENERIC, NETLINK_FIB_LOOKUP, etc.
		 *
		 * XXX - this is handled in setup_socket().
		 */
		/* handlep->cooked = 1; */
		break;

#ifndef ARPHRD_VSOCKMON
#define ARPHRD_VSOCKMON	826
#endif
	case ARPHRD_VSOCKMON:
		handle->linktype = DLT_VSOCK;
		break;

	default:
		handle->linktype = -1;
		break;
	}
	return (0);
}

/*
 * Try to set up a PF_PACKET socket.
 * Returns 0 or a PCAP_WARNING_ value on success and a PCAP_ERROR_ value
 * on failure.
 */
static int
setup_socket(pcap_t *handle, int is_any_device)
{
	struct pcap_linux *handlep = handle->priv;
	const char		*device = handle->opt.device;
	int			status = 0;
	int			sock_fd, arptype;
	int			val;
	int			err = 0;
	struct packet_mreq	mr;
#if defined(SO_BPF_EXTENSIONS) && defined(SKF_AD_VLAN_TAG_PRESENT)
	int			bpf_extensions;
	socklen_t		len = sizeof(bpf_extensions);
#endif

	/*
	 * Open a socket with protocol family packet. If cooked is true,
	 * we open a SOCK_DGRAM socket for the cooked interface, otherwise
	 * we open a SOCK_RAW socket for the raw interface.
	 *
	 * The protocol is set to 0.  This means we will receive no
	 * packets until we "bind" the socket with a non-zero
	 * protocol.  This allows us to setup the ring buffers without
	 * dropping any packets.
	 */
	sock_fd = is_any_device ?
		socket(PF_PACKET, SOCK_DGRAM, 0) :
		socket(PF_PACKET, SOCK_RAW, 0);

	if (sock_fd == -1) {
		if (errno == EPERM || errno == EACCES) {
			/*
			 * You don't have permission to open the
			 * socket.
			 */
			status = PCAP_ERROR_PERM_DENIED;
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "Attempt to create packet socket failed - CAP_NET_RAW may be required");
		} else if (errno == EAFNOSUPPORT) {
			/*
			 * PF_PACKET sockets not supported.
			 * Perhaps we're running on the WSL1 module
			 * in the Windows NT kernel rather than on
			 * a real Linux kernel.
			 */
			status = PCAP_ERROR_CAPTURE_NOTSUP;
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "PF_PACKET sockets not supported - is this WSL1?");
		} else {
			/*
			 * Other error.
			 */
			status = PCAP_ERROR;
		}
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "socket");
		return status;
	}

	/*
	 * Get the interface index of the loopback device.
	 * If the attempt fails, don't fail, just set the
	 * "handlep->lo_ifindex" to -1.
	 *
	 * XXX - can there be more than one device that loops
	 * packets back, i.e. devices other than "lo"?  If so,
	 * we'd need to find them all, and have an array of
	 * indices for them, and check all of them in
	 * "pcap_read_packet()".
	 */
	handlep->lo_ifindex = iface_get_id(sock_fd, "lo", handle->errbuf);

	/*
	 * Default value for offset to align link-layer payload
	 * on a 4-byte boundary.
	 */
	handle->offset	 = 0;

	/*
	 * What kind of frames do we have to deal with? Fall back
	 * to cooked mode if we have an unknown interface type
	 * or a type we know doesn't work well in raw mode.
	 */
	if (!is_any_device) {
		/* Assume for now we don't need cooked mode. */
		handlep->cooked = 0;

		if (handle->opt.rfmon) {
			/*
			 * We were asked to turn on monitor mode.
			 * Do so before we get the link-layer type,
			 * because entering monitor mode could change
			 * the link-layer type.
			 */
			err = enter_rfmon_mode(handle, sock_fd, device);
			if (err < 0) {
				/* Hard failure */
				close(sock_fd);
				return err;
			}
			if (err == 0) {
				/*
				 * Nothing worked for turning monitor mode
				 * on.
				 */
				close(sock_fd);

				return PCAP_ERROR_RFMON_NOTSUP;
			}

			/*
			 * Either monitor mode has been turned on for
			 * the device, or we've been given a different
			 * device to open for monitor mode.  If we've
			 * been given a different device, use it.
			 */
			if (handlep->mondevice != NULL)
				device = handlep->mondevice;
		}
		arptype	= iface_get_arptype(sock_fd, device, handle->errbuf);
		if (arptype < 0) {
			close(sock_fd);
			return arptype;
		}
		status = map_arphrd_to_dlt(handle, arptype, device, 1);
		if (status < 0) {
			close(sock_fd);
			return status;
		}
		if (handle->linktype == -1 ||
		    handle->linktype == DLT_LINUX_SLL ||
		    handle->linktype == DLT_LINUX_IRDA ||
		    handle->linktype == DLT_LINUX_LAPD ||
		    handle->linktype == DLT_NETLINK ||
		    (handle->linktype == DLT_EN10MB &&
		     (strncmp("isdn", device, 4) == 0 ||
		      strncmp("isdY", device, 4) == 0))) {
			/*
			 * Unknown interface type (-1), or a
			 * device we explicitly chose to run
			 * in cooked mode (e.g., PPP devices),
			 * or an ISDN device (whose link-layer
			 * type we can only determine by using
			 * APIs that may be different on different
			 * kernels) - reopen in cooked mode.
			 *
			 * If the type is unknown, return a warning;
			 * map_arphrd_to_dlt() has already set the
			 * warning message.
			 */
			if (close(sock_fd) == -1) {
				pcapint_fmt_errmsg_for_errno(handle->errbuf,
				    PCAP_ERRBUF_SIZE, errno, "close");
				return PCAP_ERROR;
			}
			sock_fd = socket(PF_PACKET, SOCK_DGRAM, 0);
			if (sock_fd < 0) {
				/*
				 * Fatal error.  We treat this as
				 * a generic error; we already know
				 * that we were able to open a
				 * PF_PACKET/SOCK_RAW socket, so
				 * any failure is a "this shouldn't
				 * happen" case.
				 */
				pcapint_fmt_errmsg_for_errno(handle->errbuf,
				    PCAP_ERRBUF_SIZE, errno, "socket");
				return PCAP_ERROR;
			}
			handlep->cooked = 1;

			/*
			 * Get rid of any link-layer type list
			 * we allocated - this only supports cooked
			 * capture.
			 */
			if (handle->dlt_list != NULL) {
				free(handle->dlt_list);
				handle->dlt_list = NULL;
				handle->dlt_count = 0;
			}

			if (handle->linktype == -1) {
				/*
				 * Warn that we're falling back on
				 * cooked mode; we may want to
				 * update "map_arphrd_to_dlt()"
				 * to handle the new type.
				 */
				snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
					"arptype %d not "
					"supported by libpcap - "
					"falling back to cooked "
					"socket",
					arptype);
				status = PCAP_WARNING;
			}

			/*
			 * IrDA capture is not a real "cooked" capture,
			 * it's IrLAP frames, not IP packets.  The
			 * same applies to LAPD capture.
			 */
			if (handle->linktype != DLT_LINUX_IRDA &&
			    handle->linktype != DLT_LINUX_LAPD &&
			    handle->linktype != DLT_NETLINK)
				handle->linktype = DLT_LINUX_SLL;
		}

		handlep->ifindex = iface_get_id(sock_fd, device,
		    handle->errbuf);
		if (handlep->ifindex == -1) {
			close(sock_fd);
			return PCAP_ERROR;
		}

		if ((err = iface_bind(sock_fd, handlep->ifindex,
		    handle->errbuf, 0)) != 0) {
			close(sock_fd);
			return err;
		}
	} else {
		/*
		 * The "any" device.
		 */
		if (handle->opt.rfmon) {
			/*
			 * It doesn't support monitor mode.
			 */
			close(sock_fd);
			return PCAP_ERROR_RFMON_NOTSUP;
		}

		/*
		 * It uses cooked mode.
		 * Support both DLT_LINUX_SLL and DLT_LINUX_SLL2.
		 */
		handlep->cooked = 1;
		handle->linktype = DLT_LINUX_SLL;
		handle->dlt_list = (u_int *) malloc(sizeof(u_int) * 2);
		if (handle->dlt_list == NULL) {
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno, "malloc");
			return (PCAP_ERROR);
		}
		handle->dlt_list[0] = DLT_LINUX_SLL;
		handle->dlt_list[1] = DLT_LINUX_SLL2;
		handle->dlt_count = 2;

		/*
		 * We're not bound to a device.
		 * For now, we're using this as an indication
		 * that we can't transmit; stop doing that only
		 * if we figure out how to transmit in cooked
		 * mode.
		 */
		handlep->ifindex = -1;
	}

	/*
	 * Select promiscuous mode on if "promisc" is set.
	 *
	 * Do not turn allmulti mode on if we don't select
	 * promiscuous mode - on some devices (e.g., Orinoco
	 * wireless interfaces), allmulti mode isn't supported
	 * and the driver implements it by turning promiscuous
	 * mode on, and that screws up the operation of the
	 * card as a normal networking interface, and on no
	 * other platform I know of does starting a non-
	 * promiscuous capture affect which multicast packets
	 * are received by the interface.
	 */

	/*
	 * Hmm, how can we set promiscuous mode on all interfaces?
	 * I am not sure if that is possible at all.  For now, we
	 * silently ignore attempts to turn promiscuous mode on
	 * for the "any" device (so you don't have to explicitly
	 * disable it in programs such as tcpdump).
	 */

	if (!is_any_device && handle->opt.promisc) {
		memset(&mr, 0, sizeof(mr));
		mr.mr_ifindex = handlep->ifindex;
		mr.mr_type    = PACKET_MR_PROMISC;
		if (setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		    &mr, sizeof(mr)) == -1) {
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno, "setsockopt (PACKET_ADD_MEMBERSHIP)");
			close(sock_fd);
			return PCAP_ERROR;
		}
	}

	/*
	 * Enable auxiliary data and reserve room for reconstructing
	 * VLAN headers.
	 *
	 * XXX - is enabling auxiliary data necessary, now that we
	 * only support memory-mapped capture?  The kernel's memory-mapped
	 * capture code doesn't seem to check whether auxiliary data
	 * is enabled, it seems to provide it whether it is or not.
	 */
	val = 1;
	if (setsockopt(sock_fd, SOL_PACKET, PACKET_AUXDATA, &val,
		       sizeof(val)) == -1 && errno != ENOPROTOOPT) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "setsockopt (PACKET_AUXDATA)");
		close(sock_fd);
		return PCAP_ERROR;
	}
	handle->offset += VLAN_TAG_LEN;

	/*
	 * If we're in cooked mode, make the snapshot length
	 * large enough to hold a "cooked mode" header plus
	 * 1 byte of packet data (so we don't pass a byte
	 * count of 0 to "recvfrom()").
	 * XXX - we don't know whether this will be DLT_LINUX_SLL
	 * or DLT_LINUX_SLL2, so make sure it's big enough for
	 * a DLT_LINUX_SLL2 "cooked mode" header; a snapshot length
	 * that small is silly anyway.
	 */
	if (handlep->cooked) {
		if (handle->snapshot < SLL2_HDR_LEN + 1)
			handle->snapshot = SLL2_HDR_LEN + 1;
	}
	handle->bufsize = handle->snapshot;

	/*
	 * Set the offset at which to insert VLAN tags.
	 */
	set_vlan_offset(handle);

	if (handle->opt.tstamp_precision == PCAP_TSTAMP_PRECISION_NANO) {
		int nsec_tstamps = 1;

		if (setsockopt(sock_fd, SOL_SOCKET, SO_TIMESTAMPNS, &nsec_tstamps, sizeof(nsec_tstamps)) < 0) {
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "setsockopt: unable to set SO_TIMESTAMPNS");
			close(sock_fd);
			return PCAP_ERROR;
		}
	}

	/*
	 * We've succeeded. Save the socket FD in the pcap structure.
	 */
	handle->fd = sock_fd;

#if defined(SO_BPF_EXTENSIONS) && defined(SKF_AD_VLAN_TAG_PRESENT)
	/*
	 * Can we generate special code for VLAN checks?
	 * (XXX - what if we need the special code but it's not supported
	 * by the OS?  Is that possible?)
	 */
	if (getsockopt(sock_fd, SOL_SOCKET, SO_BPF_EXTENSIONS,
	    &bpf_extensions, &len) == 0) {
		if (bpf_extensions >= SKF_AD_VLAN_TAG_PRESENT) {
			/*
			 * Yes, we can.  Request that we do so.
			 */
			handle->bpf_codegen_flags |= BPF_SPECIAL_VLAN_HANDLING;
		}
	}
#endif /* defined(SO_BPF_EXTENSIONS) && defined(SKF_AD_VLAN_TAG_PRESENT) */

	return status;
}

/*
 * Attempt to setup memory-mapped access.
 *
 * On success, returns 0 if there are no warnings or a PCAP_WARNING_ code
 * if there is a warning.
 *
 * On error, returns the appropriate error code; if that is PCAP_ERROR,
 * sets handle->errbuf to the appropriate message.
 */
static int
setup_mmapped(pcap_t *handle)
{
	struct pcap_linux *handlep = handle->priv;
	int status;

	/*
	 * Attempt to allocate a buffer to hold the contents of one
	 * packet, for use by the oneshot callback.
	 */
	handlep->oneshot_buffer = malloc(handle->snapshot);
	if (handlep->oneshot_buffer == NULL) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "can't allocate oneshot buffer");
		return PCAP_ERROR;
	}

	if (handle->opt.buffer_size == 0) {
		/* by default request 2M for the ring buffer */
		handle->opt.buffer_size = 2*1024*1024;
	}
	status = prepare_tpacket_socket(handle);
	if (status == -1) {
		free(handlep->oneshot_buffer);
		handlep->oneshot_buffer = NULL;
		return PCAP_ERROR;
	}
	status = create_ring(handle);
	if (status < 0) {
		/*
		 * Error attempting to enable memory-mapped capture;
		 * fail.  The return value is the status to return.
		 */
		free(handlep->oneshot_buffer);
		handlep->oneshot_buffer = NULL;
		return status;
	}

	/*
	 * Success.  status has been set either to 0 if there are no
	 * warnings or to a PCAP_WARNING_ value if there is a warning.
	 *
	 * handle->offset is used to get the current position into the rx ring.
	 * handle->cc is used to store the ring size.
	 */

	/*
	 * Set the timeout to use in poll() before returning.
	 */
	set_poll_timeout(handlep);

	return status;
}

/*
 * Attempt to set the socket to the specified version of the memory-mapped
 * header.
 *
 * Return 0 if we succeed; return 1 if we fail because that version isn't
 * supported; return -1 on any other error, and set handle->errbuf.
 */
static int
init_tpacket(pcap_t *handle, int version, const char *version_str)
{
	struct pcap_linux *handlep = handle->priv;
	int val = version;
	socklen_t len = sizeof(val);

	/*
	 * Probe whether kernel supports the specified TPACKET version;
	 * this also gets the length of the header for that version.
	 *
	 * This socket option was introduced in 2.6.27, which was
	 * also the first release with TPACKET_V2 support.
	 */
	if (getsockopt(handle->fd, SOL_PACKET, PACKET_HDRLEN, &val, &len) < 0) {
		if (errno == EINVAL) {
			/*
			 * EINVAL means this specific version of TPACKET
			 * is not supported. Tell the caller they can try
			 * with a different one; if they've run out of
			 * others to try, let them set the error message
			 * appropriately.
			 */
			return 1;
		}

		/*
		 * All other errors are fatal.
		 */
		if (errno == ENOPROTOOPT) {
			/*
			 * PACKET_HDRLEN isn't supported, which means
			 * that memory-mapped capture isn't supported.
			 * Indicate that in the message.
			 */
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "Kernel doesn't support memory-mapped capture; a 2.6.27 or later 2.x kernel is required, with CONFIG_PACKET_MMAP specified for 2.x kernels");
		} else {
			/*
			 * Some unexpected error.
			 */
			pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "can't get %s header len on packet socket",
			    version_str);
		}
		return -1;
	}
	handlep->tp_hdrlen = val;

	val = version;
	if (setsockopt(handle->fd, SOL_PACKET, PACKET_VERSION, &val,
			   sizeof(val)) < 0) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "can't activate %s on packet socket", version_str);
		return -1;
	}
	handlep->tp_version = version;

	return 0;
}

/*
 * Attempt to set the socket to version 3 of the memory-mapped header and,
 * if that fails because version 3 isn't supported, attempt to fall
 * back to version 2.  If version 2 isn't supported, just fail.
 *
 * Return 0 if we succeed and -1 on any other error, and set handle->errbuf.
 */
static int
prepare_tpacket_socket(pcap_t *handle)
{
	int ret;

#ifdef HAVE_TPACKET3
	/*
	 * Try setting the version to TPACKET_V3.
	 *
	 * The only mode in which buffering is done on PF_PACKET
	 * sockets, so that packets might not be delivered
	 * immediately, is TPACKET_V3 mode.
	 *
	 * The buffering cannot be disabled in that mode, so
	 * if the user has requested immediate mode, we don't
	 * use TPACKET_V3.
	 */
	if (!handle->opt.immediate) {
		ret = init_tpacket(handle, TPACKET_V3, "TPACKET_V3");
		if (ret == 0) {
			/*
			 * Success.
			 */
			return 0;
		}
		if (ret == -1) {
			/*
			 * We failed for some reason other than "the
			 * kernel doesn't support TPACKET_V3".
			 */
			return -1;
		}

		/*
		 * This means it returned 1, which means "the kernel
		 * doesn't support TPACKET_V3"; try TPACKET_V2.
		 */
	}
#endif /* HAVE_TPACKET3 */

	/*
	 * Try setting the version to TPACKET_V2.
	 */
	ret = init_tpacket(handle, TPACKET_V2, "TPACKET_V2");
	if (ret == 0) {
		/*
		 * Success.
		 */
		return 0;
	}

	if (ret == 1) {
		/*
		 * OK, the kernel supports memory-mapped capture, but
		 * not TPACKET_V2.  Set the error message appropriately.
		 */
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "Kernel doesn't support TPACKET_V2; a 2.6.27 or later kernel is required");
	}

	/*
	 * We failed.
	 */
	return -1;
}

#define MAX(a,b) ((a)>(b)?(a):(b))

/*
 * Attempt to set up memory-mapped access.
 *
 * On success, returns 0 if there are no warnings or to a PCAP_WARNING_ code
 * if there is a warning.
 *
 * On error, returns the appropriate error code; if that is PCAP_ERROR,
 * sets handle->errbuf to the appropriate message.
 */
static int
create_ring(pcap_t *handle)
{
	struct pcap_linux *handlep = handle->priv;
	unsigned i, j, frames_per_block;
#ifdef HAVE_TPACKET3
	/*
	 * For sockets using TPACKET_V2, the extra stuff at the end of a
	 * struct tpacket_req3 will be ignored, so this is OK even for
	 * those sockets.
	 */
	struct tpacket_req3 req;
#else
	struct tpacket_req req;
#endif
	socklen_t len;
	unsigned int sk_type, tp_reserve, maclen, tp_hdrlen, netoff, macoff;
	unsigned int frame_size;
	int status;

	/*
	 * Start out assuming no warnings.
	 */
	status = 0;

	/*
	 * Reserve space for VLAN tag reconstruction.
	 */
	tp_reserve = VLAN_TAG_LEN;

	/*
	 * If we're capturing in cooked mode, reserve space for
	 * a DLT_LINUX_SLL2 header; we don't know yet whether
	 * we'll be using DLT_LINUX_SLL or DLT_LINUX_SLL2, as
	 * that can be changed on an open device, so we reserve
	 * space for the larger of the two.
	 *
	 * XXX - we assume that the kernel is still adding
	 * 16 bytes of extra space, so we subtract 16 from
	 * SLL2_HDR_LEN to get the additional space needed.
	 * (Are they doing that for DLT_LINUX_SLL, the link-
	 * layer header for which is 16 bytes?)
	 *
	 * XXX - should we use TPACKET_ALIGN(SLL2_HDR_LEN - 16)?
	 */
	if (handlep->cooked)
		tp_reserve += SLL2_HDR_LEN - 16;

	/*
	 * Try to request that amount of reserve space.
	 * This must be done before creating the ring buffer.
	 */
	len = sizeof(tp_reserve);
	if (setsockopt(handle->fd, SOL_PACKET, PACKET_RESERVE,
	    &tp_reserve, len) < 0) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf,
		    PCAP_ERRBUF_SIZE, errno,
		    "setsockopt (PACKET_RESERVE)");
		return PCAP_ERROR;
	}

	switch (handlep->tp_version) {

	case TPACKET_V2:
		/* Note that with large snapshot length (say 256K, which is
		 * the default for recent versions of tcpdump, Wireshark,
		 * TShark, dumpcap or 64K, the value that "-s 0" has given for
		 * a long time with tcpdump), if we use the snapshot
		 * length to calculate the frame length, only a few frames
		 * will be available in the ring even with pretty
		 * large ring size (and a lot of memory will be unused).
		 *
		 * Ideally, we should choose a frame length based on the
		 * minimum of the specified snapshot length and the maximum
		 * packet size.  That's not as easy as it sounds; consider,
		 * for example, an 802.11 interface in monitor mode, where
		 * the frame would include a radiotap header, where the
		 * maximum radiotap header length is device-dependent.
		 *
		 * So, for now, we just do this for Ethernet devices, where
		 * there's no metadata header, and the link-layer header is
		 * fixed length.  We can get the maximum packet size by
		 * adding 18, the Ethernet header length plus the CRC length
		 * (just in case we happen to get the CRC in the packet), to
		 * the MTU of the interface; we fetch the MTU in the hopes
		 * that it reflects support for jumbo frames.  (Even if the
		 * interface is just being used for passive snooping, the
		 * driver might set the size of buffers in the receive ring
		 * based on the MTU, so that the MTU limits the maximum size
		 * of packets that we can receive.)
		 *
		 * If segmentation/fragmentation or receive offload are
		 * enabled, we can get reassembled/aggregated packets larger
		 * than MTU, but bounded to 65535 plus the Ethernet overhead,
		 * due to kernel and protocol constraints */
		frame_size = handle->snapshot;
		if (handle->linktype == DLT_EN10MB) {
			unsigned int max_frame_len;
			int mtu;
			int offload;

			mtu = iface_get_mtu(handle->fd, handle->opt.device,
			    handle->errbuf);
			if (mtu == -1)
				return PCAP_ERROR;
			offload = iface_get_offload(handle);
			if (offload == -1)
				return PCAP_ERROR;
			if (offload)
				max_frame_len = MAX(mtu, 65535);
			else
				max_frame_len = mtu;
			max_frame_len += 18;

			if (frame_size > max_frame_len)
				frame_size = max_frame_len;
		}

		/* NOTE: calculus matching those in tpacket_rcv()
		 * in linux-2.6/net/packet/af_packet.c
		 */
		len = sizeof(sk_type);
		if (getsockopt(handle->fd, SOL_SOCKET, SO_TYPE, &sk_type,
		    &len) < 0) {
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno, "getsockopt (SO_TYPE)");
			return PCAP_ERROR;
		}
		maclen = (sk_type == SOCK_DGRAM) ? 0 : MAX_LINKHEADER_SIZE;
			/* XXX: in the kernel maclen is calculated from
			 * LL_ALLOCATED_SPACE(dev) and vnet_hdr.hdr_len
			 * in:  packet_snd()           in linux-2.6/net/packet/af_packet.c
			 * then packet_alloc_skb()     in linux-2.6/net/packet/af_packet.c
			 * then sock_alloc_send_pskb() in linux-2.6/net/core/sock.c
			 * but I see no way to get those sizes in userspace,
			 * like for instance with an ifreq ioctl();
			 * the best thing I've found so far is MAX_HEADER in
			 * the kernel part of linux-2.6/include/linux/netdevice.h
			 * which goes up to 128+48=176; since pcap-linux.c
			 * defines a MAX_LINKHEADER_SIZE of 256 which is
			 * greater than that, let's use it.. maybe is it even
			 * large enough to directly replace macoff..
			 */
		tp_hdrlen = TPACKET_ALIGN(handlep->tp_hdrlen) + sizeof(struct sockaddr_ll) ;
		netoff = TPACKET_ALIGN(tp_hdrlen + (maclen < 16 ? 16 : maclen)) + tp_reserve;
			/* NOTE: AFAICS tp_reserve may break the TPACKET_ALIGN
			 * of netoff, which contradicts
			 * linux-2.6/Documentation/networking/packet_mmap.txt
			 * documenting that:
			 * "- Gap, chosen so that packet data (Start+tp_net)
			 * aligns to TPACKET_ALIGNMENT=16"
			 */
			/* NOTE: in linux-2.6/include/linux/skbuff.h:
			 * "CPUs often take a performance hit
			 *  when accessing unaligned memory locations"
			 */
		macoff = netoff - maclen;
		req.tp_frame_size = TPACKET_ALIGN(macoff + frame_size);
		/*
		 * Round the buffer size up to a multiple of the
		 * frame size (rather than rounding down, which
		 * would give a buffer smaller than our caller asked
		 * for, and possibly give zero frames if the requested
		 * buffer size is too small for one frame).
		 */
		req.tp_frame_nr = (handle->opt.buffer_size + req.tp_frame_size - 1)/req.tp_frame_size;
		break;

#ifdef HAVE_TPACKET3
	case TPACKET_V3:
		/* The "frames" for this are actually buffers that
		 * contain multiple variable-sized frames.
		 *
		 * We pick a "frame" size of MAXIMUM_SNAPLEN to leave
		 * enough room for at least one reasonably-sized packet
		 * in the "frame". */
		req.tp_frame_size = MAXIMUM_SNAPLEN;
		/*
		 * Round the buffer size up to a multiple of the
		 * "frame" size (rather than rounding down, which
		 * would give a buffer smaller than our caller asked
		 * for, and possibly give zero "frames" if the requested
		 * buffer size is too small for one "frame").
		 */
		req.tp_frame_nr = (handle->opt.buffer_size + req.tp_frame_size - 1)/req.tp_frame_size;
		break;
#endif
	default:
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "Internal error: unknown TPACKET_ value %u",
		    handlep->tp_version);
		return PCAP_ERROR;
	}

	/* compute the minimum block size that will handle this frame.
	 * The block has to be page size aligned.
	 * The max block size allowed by the kernel is arch-dependent and
	 * it's not explicitly checked here. */
	req.tp_block_size = getpagesize();
	while (req.tp_block_size < req.tp_frame_size)
		req.tp_block_size <<= 1;

	frames_per_block = req.tp_block_size/req.tp_frame_size;

	/*
	 * PACKET_TIMESTAMP was added after linux/net_tstamp.h was,
	 * so we check for PACKET_TIMESTAMP.  We check for
	 * linux/net_tstamp.h just in case a system somehow has
	 * PACKET_TIMESTAMP but not linux/net_tstamp.h; that might
	 * be unnecessary.
	 *
	 * SIOCSHWTSTAMP was introduced in the patch that introduced
	 * linux/net_tstamp.h, so we don't bother checking whether
	 * SIOCSHWTSTAMP is defined (if your Linux system has
	 * linux/net_tstamp.h but doesn't define SIOCSHWTSTAMP, your
	 * Linux system is badly broken).
	 */
#if defined(HAVE_LINUX_NET_TSTAMP_H) && defined(PACKET_TIMESTAMP)
	/*
	 * If we were told to do so, ask the kernel and the driver
	 * to use hardware timestamps.
	 *
	 * Hardware timestamps are only supported with mmapped
	 * captures.
	 */
	if (handle->opt.tstamp_type == PCAP_TSTAMP_ADAPTER ||
	    handle->opt.tstamp_type == PCAP_TSTAMP_ADAPTER_UNSYNCED) {
		struct hwtstamp_config hwconfig;
		struct ifreq ifr;
		int timesource;

		/*
		 * Ask for hardware time stamps on all packets,
		 * including transmitted packets.
		 */
		memset(&hwconfig, 0, sizeof(hwconfig));
		hwconfig.tx_type = HWTSTAMP_TX_ON;
		hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;

		memset(&ifr, 0, sizeof(ifr));
		pcapint_strlcpy(ifr.ifr_name, handle->opt.device, sizeof(ifr.ifr_name));
		ifr.ifr_data = (void *)&hwconfig;

		/*
		 * This may require CAP_NET_ADMIN.
		 */
		if (ioctl(handle->fd, SIOCSHWTSTAMP, &ifr) < 0) {
			switch (errno) {

			case EPERM:
				/*
				 * Treat this as an error, as the
				 * user should try to run this
				 * with the appropriate privileges -
				 * and, if they can't, shouldn't
				 * try requesting hardware time stamps.
				 */
				snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				    "Attempt to set hardware timestamp failed - CAP_NET_ADMIN may be required");
				return PCAP_ERROR_PERM_DENIED;

			case EOPNOTSUPP:
			case ERANGE:
				/*
				 * Treat this as a warning, as the
				 * only way to fix the warning is to
				 * get an adapter that supports hardware
				 * time stamps for *all* packets.
				 * (ERANGE means "we support hardware
				 * time stamps, but for packets matching
				 * that particular filter", so it means
				 * "we don't support hardware time stamps
				 * for all incoming packets" here.)
				 *
				 * We'll just fall back on the standard
				 * host time stamps.
				 */
				status = PCAP_WARNING_TSTAMP_TYPE_NOTSUP;
				break;

			default:
				pcapint_fmt_errmsg_for_errno(handle->errbuf,
				    PCAP_ERRBUF_SIZE, errno,
				    "SIOCSHWTSTAMP failed");
				return PCAP_ERROR;
			}
		} else {
			/*
			 * Well, that worked.  Now specify the type of
			 * hardware time stamp we want for this
			 * socket.
			 */
			if (handle->opt.tstamp_type == PCAP_TSTAMP_ADAPTER) {
				/*
				 * Hardware timestamp, synchronized
				 * with the system clock.
				 */
				timesource = SOF_TIMESTAMPING_SYS_HARDWARE;
			} else {
				/*
				 * PCAP_TSTAMP_ADAPTER_UNSYNCED - hardware
				 * timestamp, not synchronized with the
				 * system clock.
				 */
				timesource = SOF_TIMESTAMPING_RAW_HARDWARE;
			}
			if (setsockopt(handle->fd, SOL_PACKET, PACKET_TIMESTAMP,
				(void *)&timesource, sizeof(timesource))) {
				pcapint_fmt_errmsg_for_errno(handle->errbuf,
				    PCAP_ERRBUF_SIZE, errno,
				    "can't set PACKET_TIMESTAMP");
				return PCAP_ERROR;
			}
		}
	}
#endif /* HAVE_LINUX_NET_TSTAMP_H && PACKET_TIMESTAMP */

	/* ask the kernel to create the ring */
retry:
	req.tp_block_nr = req.tp_frame_nr / frames_per_block;

	/* req.tp_frame_nr is requested to match frames_per_block*req.tp_block_nr */
	req.tp_frame_nr = req.tp_block_nr * frames_per_block;

#ifdef HAVE_TPACKET3
	/* timeout value to retire block - use the configured buffering timeout, or default if <0. */
	if (handlep->timeout > 0) {
		/* Use the user specified timeout as the block timeout */
		req.tp_retire_blk_tov = handlep->timeout;
	} else if (handlep->timeout == 0) {
		/*
		 * In pcap, this means "infinite timeout"; TPACKET_V3
		 * doesn't support that, so just set it to UINT_MAX
		 * milliseconds.  In the TPACKET_V3 loop, if the
		 * timeout is 0, and we haven't yet seen any packets,
		 * and we block and still don't have any packets, we
		 * keep blocking until we do.
		 */
		req.tp_retire_blk_tov = UINT_MAX;
	} else {
		/*
		 * XXX - this is not valid; use 0, meaning "have the
		 * kernel pick a default", for now.
		 */
		req.tp_retire_blk_tov = 0;
	}
	/* private data not used */
	req.tp_sizeof_priv = 0;
	/* Rx ring - feature request bits - none (rxhash will not be filled) */
	req.tp_feature_req_word = 0;
#endif

	if (setsockopt(handle->fd, SOL_PACKET, PACKET_RX_RING,
					(void *) &req, sizeof(req))) {
		if ((errno == ENOMEM) && (req.tp_block_nr > 1)) {
			/*
			 * Memory failure; try to reduce the requested ring
			 * size.
			 *
			 * We used to reduce this by half -- do 5% instead.
			 * That may result in more iterations and a longer
			 * startup, but the user will be much happier with
			 * the resulting buffer size.
			 */
			if (req.tp_frame_nr < 20)
				req.tp_frame_nr -= 1;
			else
				req.tp_frame_nr -= req.tp_frame_nr/20;
			goto retry;
		}
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "can't create rx ring on packet socket");
		return PCAP_ERROR;
	}

	/* memory map the rx ring */
	handlep->mmapbuflen = req.tp_block_nr * req.tp_block_size;
	handlep->mmapbuf = mmap(0, handlep->mmapbuflen,
	    PROT_READ|PROT_WRITE, MAP_SHARED, handle->fd, 0);
	if (handlep->mmapbuf == MAP_FAILED) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "can't mmap rx ring");

		/* clear the allocated ring on error*/
		destroy_ring(handle);
		return PCAP_ERROR;
	}

	/* allocate a ring for each frame header pointer*/
	handle->cc = req.tp_frame_nr;
	handle->buffer = malloc(handle->cc * sizeof(union thdr *));
	if (!handle->buffer) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "can't allocate ring of frame headers");

		destroy_ring(handle);
		return PCAP_ERROR;
	}

	/* fill the header ring with proper frame ptr*/
	handle->offset = 0;
	for (i=0; i<req.tp_block_nr; ++i) {
		u_char *base = &handlep->mmapbuf[i*req.tp_block_size];
		for (j=0; j<frames_per_block; ++j, ++handle->offset) {
			RING_GET_CURRENT_FRAME(handle) = base;
			base += req.tp_frame_size;
		}
	}

	handle->bufsize = req.tp_frame_size;
	handle->offset = 0;
	return status;
}

/* free all ring related resources*/
static void
destroy_ring(pcap_t *handle)
{
	struct pcap_linux *handlep = handle->priv;

	/*
	 * Tell the kernel to destroy the ring.
	 * We don't check for setsockopt failure, as 1) we can't recover
	 * from an error and 2) we might not yet have set it up in the
	 * first place.
	 */
	struct tpacket_req req;
	memset(&req, 0, sizeof(req));
	(void)setsockopt(handle->fd, SOL_PACKET, PACKET_RX_RING,
				(void *) &req, sizeof(req));

	/* if ring is mapped, unmap it*/
	if (handlep->mmapbuf) {
		/* do not test for mmap failure, as we can't recover from any error */
		(void)munmap(handlep->mmapbuf, handlep->mmapbuflen);
		handlep->mmapbuf = NULL;
	}
}

/*
 * Special one-shot callback, used for pcap_next() and pcap_next_ex(),
 * for Linux mmapped capture.
 *
 * The problem is that pcap_next() and pcap_next_ex() expect the packet
 * data handed to the callback to be valid after the callback returns,
 * but pcap_read_linux_mmap() has to release that packet as soon as
 * the callback returns (otherwise, the kernel thinks there's still
 * at least one unprocessed packet available in the ring, so a select()
 * will immediately return indicating that there's data to process), so,
 * in the callback, we have to make a copy of the packet.
 *
 * Yes, this means that, if the capture is using the ring buffer, using
 * pcap_next() or pcap_next_ex() requires more copies than using
 * pcap_loop() or pcap_dispatch().  If that bothers you, don't use
 * pcap_next() or pcap_next_ex().
 */
static void
pcapint_oneshot_linux(u_char *user, const struct pcap_pkthdr *h,
    const u_char *bytes)
{
	struct oneshot_userdata *sp = (struct oneshot_userdata *)user;
	pcap_t *handle = sp->pd;
	struct pcap_linux *handlep = handle->priv;

	*sp->hdr = *h;
	memcpy(handlep->oneshot_buffer, bytes, h->caplen);
	*sp->pkt = handlep->oneshot_buffer;
}

static int
pcap_getnonblock_linux(pcap_t *handle)
{
	struct pcap_linux *handlep = handle->priv;

	/* use negative value of timeout to indicate non blocking ops */
	return (handlep->timeout<0);
}

static int
pcap_setnonblock_linux(pcap_t *handle, int nonblock)
{
	struct pcap_linux *handlep = handle->priv;

	/*
	 * Set the file descriptor to the requested mode, as we use
	 * it for sending packets.
	 */
	if (pcapint_setnonblock_fd(handle, nonblock) == -1)
		return -1;

	/*
	 * Map each value to their corresponding negation to
	 * preserve the timeout value provided with pcap_set_timeout.
	 */
	if (nonblock) {
		/*
		 * We're setting the mode to non-blocking mode.
		 */
		if (handlep->timeout >= 0) {
			/*
			 * Indicate that we're switching to
			 * non-blocking mode.
			 */
			handlep->timeout = ~handlep->timeout;
		}
		if (handlep->poll_breakloop_fd != -1) {
			/* Close the eventfd; we do not need it in nonblock mode. */
			close(handlep->poll_breakloop_fd);
			handlep->poll_breakloop_fd = -1;
		}
	} else {
		/*
		 * We're setting the mode to blocking mode.
		 */
		if (handlep->poll_breakloop_fd == -1) {
			/* If we did not have an eventfd, open one now that we are blocking. */
			if ( ( handlep->poll_breakloop_fd = eventfd(0, EFD_NONBLOCK) ) == -1 ) {
				pcapint_fmt_errmsg_for_errno(handle->errbuf,
				    PCAP_ERRBUF_SIZE, errno,
				    "could not open eventfd");
				return -1;
			}
		}
		if (handlep->timeout < 0) {
			handlep->timeout = ~handlep->timeout;
		}
	}
	/* Update the timeout to use in poll(). */
	set_poll_timeout(handlep);
	return 0;
}

/*
 * Get the status field of the ring buffer frame at a specified offset.
 */
static inline u_int
pcap_get_ring_frame_status(pcap_t *handle, int offset)
{
	struct pcap_linux *handlep = handle->priv;
	union thdr h;

	h.raw = RING_GET_FRAME_AT(handle, offset);
	switch (handlep->tp_version) {
	case TPACKET_V2:
		return __atomic_load_n(&h.h2->tp_status, __ATOMIC_ACQUIRE);
		break;
#ifdef HAVE_TPACKET3
	case TPACKET_V3:
		return __atomic_load_n(&h.h3->hdr.bh1.block_status, __ATOMIC_ACQUIRE);
		break;
#endif
	}
	/* This should not happen. */
	return 0;
}

/*
 * Block waiting for frames to be available.
 */
static int pcap_wait_for_frames_mmap(pcap_t *handle)
{
	struct pcap_linux *handlep = handle->priv;
	int timeout;
	struct ifreq ifr;
	int ret;
	struct pollfd pollinfo[2];
	int numpollinfo;
	pollinfo[0].fd = handle->fd;
	pollinfo[0].events = POLLIN;
	if ( handlep->poll_breakloop_fd == -1 ) {
		numpollinfo = 1;
		pollinfo[1].revents = 0;
		/*
		 * We set pollinfo[1].revents to zero, even though
		 * numpollinfo = 1 meaning that poll() doesn't see
		 * pollinfo[1], so that we do not have to add a
		 * conditional of numpollinfo > 1 below when we
		 * test pollinfo[1].revents.
		 */
	} else {
		pollinfo[1].fd = handlep->poll_breakloop_fd;
		pollinfo[1].events = POLLIN;
		numpollinfo = 2;
	}

	/*
	 * Keep polling until we either get some packets to read, see
	 * that we got told to break out of the loop, get a fatal error,
	 * or discover that the device went away.
	 *
	 * In non-blocking mode, we must still do one poll() to catch
	 * any pending error indications, but the poll() has a timeout
	 * of 0, so that it doesn't block, and we quit after that one
	 * poll().
	 *
	 * If we've seen an ENETDOWN, it might be the first indication
	 * that the device went away, or it might just be that it was
	 * configured down.  Unfortunately, there's no guarantee that
	 * the device has actually been removed as an interface, because:
	 *
	 * 1) if, as appears to be the case at least some of the time,
	 * the PF_PACKET socket code first gets a NETDEV_DOWN indication
	 * for the device and then gets a NETDEV_UNREGISTER indication
	 * for it, the first indication will cause a wakeup with ENETDOWN
	 * but won't set the packet socket's field for the interface index
	 * to -1, and the second indication won't cause a wakeup (because
	 * the first indication also caused the protocol hook to be
	 * unregistered) but will set the packet socket's field for the
	 * interface index to -1;
	 *
	 * 2) even if just a NETDEV_UNREGISTER indication is registered,
	 * the packet socket's field for the interface index only gets
	 * set to -1 after the wakeup, so there's a small but non-zero
	 * risk that a thread blocked waiting for the wakeup will get
	 * to the "fetch the socket name" code before the interface index
	 * gets set to -1, so it'll get the old interface index.
	 *
	 * Therefore, if we got an ENETDOWN and haven't seen a packet
	 * since then, we assume that we might be waiting for the interface
	 * to disappear, and poll with a timeout to try again in a short
	 * period of time.  If we *do* see a packet, the interface has
	 * come back up again, and is *definitely* still there, so we
	 * don't need to poll.
	 */
	for (;;) {
		/*
		 * Yes, we do this even in non-blocking mode, as it's
		 * the only way to get error indications from a
		 * tpacket socket.
		 *
		 * The timeout is 0 in non-blocking mode, so poll()
		 * returns immediately.
		 */
		timeout = handlep->poll_timeout;

		/*
		 * If we got an ENETDOWN and haven't gotten an indication
		 * that the device has gone away or that the device is up,
		 * we don't yet know for certain whether the device has
		 * gone away or not, do a poll() with a 1-millisecond timeout,
		 * as we have to poll indefinitely for "device went away"
		 * indications until we either get one or see that the
		 * device is up.
		 */
		if (handlep->netdown) {
			if (timeout != 0)
				timeout = 1;
		}
		ret = poll(pollinfo, numpollinfo, timeout);
		if (ret < 0) {
			/*
			 * Error.  If it's not EINTR, report it.
			 */
			if (errno != EINTR) {
				pcapint_fmt_errmsg_for_errno(handle->errbuf,
				    PCAP_ERRBUF_SIZE, errno,
				    "can't poll on packet socket");
				return PCAP_ERROR;
			}

			/*
			 * It's EINTR; if we were told to break out of
			 * the loop, do so.
			 */
			if (handle->break_loop) {
				handle->break_loop = 0;
				return PCAP_ERROR_BREAK;
			}
		} else if (ret > 0) {
			/*
			 * OK, some descriptor is ready.
			 * Check the socket descriptor first.
			 *
			 * As I read the Linux man page, pollinfo[0].revents
			 * will either be POLLIN, POLLERR, POLLHUP, or POLLNVAL.
			 */
			if (pollinfo[0].revents == POLLIN) {
				/*
				 * OK, we may have packets to
				 * read.
				 */
				break;
			}
			if (pollinfo[0].revents != 0) {
				/*
				 * There's some indication other than
				 * "you can read on this descriptor" on
				 * the descriptor.
				 */
				if (pollinfo[0].revents & POLLNVAL) {
					snprintf(handle->errbuf,
					    PCAP_ERRBUF_SIZE,
					    "Invalid polling request on packet socket");
					return PCAP_ERROR;
				}
				if (pollinfo[0].revents & (POLLHUP | POLLRDHUP)) {
					snprintf(handle->errbuf,
					    PCAP_ERRBUF_SIZE,
					    "Hangup on packet socket");
					return PCAP_ERROR;
				}
				if (pollinfo[0].revents & POLLERR) {
					/*
					 * Get the error.
					 */
					int err;
					socklen_t errlen;

					errlen = sizeof(err);
					if (getsockopt(handle->fd, SOL_SOCKET,
					    SO_ERROR, &err, &errlen) == -1) {
						/*
						 * The call *itself* returned
						 * an error; make *that*
						 * the error.
						 */
						err = errno;
					}

					/*
					 * OK, we have the error.
					 */
					if (err == ENETDOWN) {
						/*
						 * The device on which we're
						 * capturing went away or the
						 * interface was taken down.
						 *
						 * We don't know for certain
						 * which happened, and the
						 * next poll() may indicate
						 * that there are packets
						 * to be read, so just set
						 * a flag to get us to do
						 * checks later, and set
						 * the required select
						 * timeout to 1 millisecond
						 * so that event loops that
						 * check our socket descriptor
						 * also time out so that
						 * they can call us and we
						 * can do the checks.
						 */
						handlep->netdown = 1;
						handle->required_select_timeout = &netdown_timeout;
					} else if (err == 0) {
						/*
						 * This shouldn't happen, so
						 * report a special indication
						 * that it did.
						 */
						snprintf(handle->errbuf,
						    PCAP_ERRBUF_SIZE,
						    "Error condition on packet socket: Reported error was 0");
						return PCAP_ERROR;
					} else {
						pcapint_fmt_errmsg_for_errno(handle->errbuf,
						    PCAP_ERRBUF_SIZE,
						    err,
						    "Error condition on packet socket");
						return PCAP_ERROR;
					}
				}
			}
			/*
			 * Now check the event device.
			 */
			if (pollinfo[1].revents & POLLIN) {
				ssize_t nread;
				uint64_t value;

				/*
				 * This should never fail, but, just
				 * in case....
				 */
				nread = read(handlep->poll_breakloop_fd, &value,
				    sizeof(value));
				if (nread == -1) {
					pcapint_fmt_errmsg_for_errno(handle->errbuf,
					    PCAP_ERRBUF_SIZE,
					    errno,
					    "Error reading from event FD");
					return PCAP_ERROR;
				}

				/*
				 * According to the Linux read(2) man
				 * page, read() will transfer at most
				 * 2^31-1 bytes, so the return value is
				 * either -1 or a value between 0
				 * and 2^31-1, so it's non-negative.
				 *
				 * Cast it to size_t to squelch
				 * warnings from the compiler; add this
				 * comment to squelch warnings from
				 * humans reading the code. :-)
				 *
				 * Don't treat an EOF as an error, but
				 * *do* treat a short read as an error;
				 * that "shouldn't happen", but....
				 */
				if (nread != 0 &&
				    (size_t)nread < sizeof(value)) {
					snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
					    "Short read from event FD: expected %zu, got %zd",
					    sizeof(value), nread);
					return PCAP_ERROR;
				}

				/*
				 * This event gets signaled by a
				 * pcap_breakloop() call; if we were told
				 * to break out of the loop, do so.
				 */
				if (handle->break_loop) {
					handle->break_loop = 0;
					return PCAP_ERROR_BREAK;
				}
			}
		}

		/*
		 * Either:
		 *
		 *   1) we got neither an error from poll() nor any
		 *      readable descriptors, in which case there
		 *      are no packets waiting to read
		 *
		 * or
		 *
		 *   2) We got readable descriptors but the PF_PACKET
		 *      socket wasn't one of them, in which case there
		 *      are no packets waiting to read
		 *
		 * so, if we got an ENETDOWN, we've drained whatever
		 * packets were available to read at the point of the
		 * ENETDOWN.
		 *
		 * So, if we got an ENETDOWN and haven't gotten an indication
		 * that the device has gone away or that the device is up,
		 * we don't yet know for certain whether the device has
		 * gone away or not, check whether the device exists and is
		 * up.
		 */
		if (handlep->netdown) {
			if (!device_still_exists(handle)) {
				/*
				 * The device doesn't exist any more;
				 * report that.
				 *
				 * XXX - we should really return an
				 * appropriate error for that, but
				 * pcap_dispatch() etc. aren't documented
				 * as having error returns other than
				 * PCAP_ERROR or PCAP_ERROR_BREAK.
				 */
				snprintf(handle->errbuf,  PCAP_ERRBUF_SIZE,
				    "The interface disappeared");
				return PCAP_ERROR;
			}

			/*
			 * The device still exists; try to see if it's up.
			 */
			memset(&ifr, 0, sizeof(ifr));
			pcapint_strlcpy(ifr.ifr_name, handlep->device,
			    sizeof(ifr.ifr_name));
			if (ioctl(handle->fd, SIOCGIFFLAGS, &ifr) == -1) {
				if (errno == ENXIO || errno == ENODEV) {
					/*
					 * OK, *now* it's gone.
					 *
					 * XXX - see above comment.
					 */
					snprintf(handle->errbuf,
					    PCAP_ERRBUF_SIZE,
					    "The interface disappeared");
					return PCAP_ERROR;
				} else {
					pcapint_fmt_errmsg_for_errno(handle->errbuf,
					    PCAP_ERRBUF_SIZE, errno,
					    "%s: Can't get flags",
					    handlep->device);
					return PCAP_ERROR;
				}
			}
			if (ifr.ifr_flags & IFF_UP) {
				/*
				 * It's up, so it definitely still exists.
				 * Cancel the ENETDOWN indication - we
				 * presumably got it due to the interface
				 * going down rather than the device going
				 * away - and revert to "no required select
				 * timeout.
				 */
				handlep->netdown = 0;
				handle->required_select_timeout = NULL;
			}
		}

		/*
		 * If we're in non-blocking mode, just quit now, rather
		 * than spinning in a loop doing poll()s that immediately
		 * time out if there's no indication on any descriptor.
		 */
		if (handlep->poll_timeout == 0)
			break;
	}
	return 0;
}

/* handle a single memory mapped packet */
static int pcap_handle_packet_mmap(
		pcap_t *handle,
		pcap_handler callback,
		u_char *user,
		unsigned char *frame,
		unsigned int tp_len,
		unsigned int tp_mac,
		unsigned int tp_snaplen,
		unsigned int tp_sec,
		unsigned int tp_usec,
		int tp_vlan_tci_valid,
		__u16 tp_vlan_tci,
		__u16 tp_vlan_tpid)
{
	struct pcap_linux *handlep = handle->priv;
	unsigned char *bp;
	struct sockaddr_ll *sll;
	struct pcap_pkthdr pcaphdr;
	unsigned int snaplen = tp_snaplen;
	struct utsname utsname;

	/* perform sanity check on internal offset. */
	if (tp_mac + tp_snaplen > handle->bufsize) {
		/*
		 * Report some system information as a debugging aid.
		 */
		if (uname(&utsname) != -1) {
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				"corrupted frame on kernel ring mac "
				"offset %u + caplen %u > frame len %d "
				"(kernel %.32s version %s, machine %.16s)",
				tp_mac, tp_snaplen, handle->bufsize,
				utsname.release, utsname.version,
				utsname.machine);
		} else {
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				"corrupted frame on kernel ring mac "
				"offset %u + caplen %u > frame len %d",
				tp_mac, tp_snaplen, handle->bufsize);
		}
		return -1;
	}

	/* run filter on received packet
	 * If the kernel filtering is enabled we need to run the
	 * filter until all the frames present into the ring
	 * at filter creation time are processed.
	 * In this case, blocks_to_filter_in_userland is used
	 * as a counter for the packet we need to filter.
	 * Note: alternatively it could be possible to stop applying
	 * the filter when the ring became empty, but it can possibly
	 * happen a lot later... */
	bp = frame + tp_mac;

	/* if required build in place the sll header*/
	sll = (void *)(frame + TPACKET_ALIGN(handlep->tp_hdrlen));
	if (handlep->cooked) {
		if (handle->linktype == DLT_LINUX_SLL2) {
			struct sll2_header *hdrp;

			/*
			 * The kernel should have left us with enough
			 * space for an sll header; back up the packet
			 * data pointer into that space, as that'll be
			 * the beginning of the packet we pass to the
			 * callback.
			 */
			bp -= SLL2_HDR_LEN;

			/*
			 * Let's make sure that's past the end of
			 * the tpacket header, i.e. >=
			 * ((u_char *)thdr + TPACKET_HDRLEN), so we
			 * don't step on the header when we construct
			 * the sll header.
			 */
			if (bp < (u_char *)frame +
					   TPACKET_ALIGN(handlep->tp_hdrlen) +
					   sizeof(struct sockaddr_ll)) {
				snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
					"cooked-mode frame doesn't have room for sll header");
				return -1;
			}

			/*
			 * OK, that worked; construct the sll header.
			 */
			hdrp = (struct sll2_header *)bp;
			hdrp->sll2_protocol = sll->sll_protocol;
			hdrp->sll2_reserved_mbz = 0;
			hdrp->sll2_if_index = htonl(sll->sll_ifindex);
			hdrp->sll2_hatype = htons(sll->sll_hatype);
			hdrp->sll2_pkttype = sll->sll_pkttype;
			hdrp->sll2_halen = sll->sll_halen;
			memcpy(hdrp->sll2_addr, sll->sll_addr, SLL_ADDRLEN);

			snaplen += sizeof(struct sll2_header);
		} else {
			struct sll_header *hdrp;

			/*
			 * The kernel should have left us with enough
			 * space for an sll header; back up the packet
			 * data pointer into that space, as that'll be
			 * the beginning of the packet we pass to the
			 * callback.
			 */
			bp -= SLL_HDR_LEN;

			/*
			 * Let's make sure that's past the end of
			 * the tpacket header, i.e. >=
			 * ((u_char *)thdr + TPACKET_HDRLEN), so we
			 * don't step on the header when we construct
			 * the sll header.
			 */
			if (bp < (u_char *)frame +
					   TPACKET_ALIGN(handlep->tp_hdrlen) +
					   sizeof(struct sockaddr_ll)) {
				snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
					"cooked-mode frame doesn't have room for sll header");
				return -1;
			}

			/*
			 * OK, that worked; construct the sll header.
			 */
			hdrp = (struct sll_header *)bp;
			hdrp->sll_pkttype = htons(sll->sll_pkttype);
			hdrp->sll_hatype = htons(sll->sll_hatype);
			hdrp->sll_halen = htons(sll->sll_halen);
			memcpy(hdrp->sll_addr, sll->sll_addr, SLL_ADDRLEN);
			hdrp->sll_protocol = sll->sll_protocol;

			snaplen += sizeof(struct sll_header);
		}
	} else {
		/*
		 * If this is a packet from a CAN device, so that
		 * sll->sll_hatype is ARPHRD_CAN, then, as we're
		 * not capturing in cooked mode, its link-layer
		 * type is DLT_CAN_SOCKETCAN.  Fix up the header
		 * provided by the code below us to match what
		 * DLT_CAN_SOCKETCAN is expected to provide.
		 */
		if (sll->sll_hatype == ARPHRD_CAN) {
			pcap_can_socketcan_hdr *canhdr = (pcap_can_socketcan_hdr *)bp;
			uint16_t protocol = ntohs(sll->sll_protocol);

			/*
			 * Check the protocol field from the sll header.
			 * If it's one of the known CAN protocol types,
			 * make sure the appropriate flags are set, so
			 * that a program can tell what type of frame
			 * it is.
			 *
			 * The two flags are:
			 *
			 *   CANFD_FDF, which is in the fd_flags field
			 *   of the CAN classic/CAN FD header;
			 *
			 *   CANXL_XLF, which is in the flags field
			 *   of the CAN XL header, which overlaps
			 *   the payload_length field of the CAN
			 *   classic/CAN FD header.
			 */
			switch (protocol) {

			case LINUX_SLL_P_CAN:
				/*
				 * CAN classic.
				 *
				 * Zero out the fd_flags and reserved
				 * fields, in case they're uninitialized
				 * crap, and clear the CANXL_XLF bit in
				 * the payload_length field.
				 *
				 * This means that the CANFD_FDF flag isn't
				 * set in the fd_flags field, and that
				 * the CANXL_XLF bit isn't set in the
				 * payload_length field, so this frame
				 * will appear to be a CAN classic frame.
				 */
				canhdr->payload_length &= ~CANXL_XLF;
				canhdr->fd_flags = 0;
				canhdr->reserved1 = 0;
				canhdr->reserved2 = 0;
				break;

			case LINUX_SLL_P_CANFD:
				/*
				 * Set CANFD_FDF in the fd_flags field,
				 * and clear the CANXL_XLF bit in the
				 * payload_length field, so this frame
				 * will appear to be a CAN FD frame.
				 */
				canhdr->payload_length &= ~CANXL_XLF;
				canhdr->fd_flags |= CANFD_FDF;

				/*
				 * Zero out all the unknown bits in fd_flags
				 * and clear the reserved fields, so that
				 * a program reading this can assume that
				 * CANFD_FDF is set because we set it, not
				 * because some uninitialized crap was
				 * provided in the fd_flags field.
				 *
				 * (At least some LINKTYPE_CAN_SOCKETCAN
				 * files attached to Wireshark bugs had
				 * uninitialized junk there, so it does
				 * happen.)
				 *
				 * Update this if Linux adds more flag bits
				 * to the fd_flags field or uses either of
				 * the reserved fields for FD frames.
				 */
				canhdr->fd_flags &= (CANFD_FDF|CANFD_ESI|CANFD_BRS);
				canhdr->reserved1 = 0;
				canhdr->reserved2 = 0;
				break;

			case LINUX_SLL_P_CANXL:
				/*
				 * CAN XL frame.
				 *
				 * Make sure the CANXL_XLF bit is set in
				 * the payload_length field, so that
				 * this frame will appear to be a
				 * CAN XL frame.
				 */
				canhdr->payload_length |= CANXL_XLF;
				break;
			}

			/*
			 * Put multi-byte header fields in a byte-order
			 *-independent format.
			 */
			if (canhdr->payload_length & CANXL_XLF) {
				/*
				 * This is a CAN XL frame.
				 *
				 * DLT_CAN_SOCKETCAN is specified as having
				 * the Priority ID/VCID field in big--
				 * endian byte order, and the payload length
				 * and Acceptance Field in little-endian byte
				 * order. but capturing on a CAN device
				 * provides them in host byte order.
				 * Convert them to the appropriate byte
				 * orders.
				 *
				 * The reason we put the first field
				 * into big-endian byte order is that
				 * older libpcap code, ignorant of
				 * CAN XL, treated it as the CAN ID
				 * field and put it into big-endian
				 * byte order, and we don't want to
				 * break code that understands CAN XL
				 * headers, and treats that field as
				 * being big-endian.
				 *
				 * The other fields are put in little-
				 * endian byte order is that older
				 * libpcap code, ignorant of CAN XL,
				 * left those fields alone, and the
				 * processors on which the CAN XL
				 * frames were captured are likely
				 * to be little-endian processors.
				 */
				pcap_can_socketcan_xl_hdr *canxl_hdr = (pcap_can_socketcan_xl_hdr *)bp;

#if __BYTE_ORDER == __LITTLE_ENDIAN
				/*
				 * We're capturing on a little-endian
				 * machine, so we put the priority/VCID
				 * field into big-endian byte order, and
				 * leave the payload length and acceptance
				 * field in little-endian byte order.
				 */
				/* Byte-swap priority/VCID. */
				canxl_hdr->priority_vcid = SWAPLONG(canxl_hdr->priority_vcid);
#elif __BYTE_ORDER == __BIG_ENDIAN
				/*
				 * We're capturing on a big-endian
				 * machine, so we want to leave the
				 * priority/VCID field alone, and byte-swap
				 * the payload length and acceptance
				 * fields to little-endian.
				 */
				/* Byte-swap the payload length */
				canxl_hdr->payload_length = SWAPSHORT(canxl_hdr->payload_length);

				/*
				 * Byte-swap the acceptance field.
				 *
				 * XXX - is it just a 4-octet string,
				 * not in any byte order?
				 */
				canxl_hdr->acceptance_field = SWAPLONG(canxl_hdr->acceptance_field);
#else
#error "Unknown byte order"
#endif
			} else {
				/*
				 * CAN or CAN FD frame.
				 *
				 * DLT_CAN_SOCKETCAN is specified as having
				 * the CAN ID and flags in network byte
				 * order, but capturing on a CAN device
				 * provides it in host byte order.  Convert
				 * it to network byte order.
				 */
				canhdr->can_id = htonl(canhdr->can_id);
			}
		}
	}

	if (handlep->filter_in_userland && handle->fcode.bf_insns) {
		struct pcap_bpf_aux_data aux_data;

		aux_data.vlan_tag_present = tp_vlan_tci_valid;
		aux_data.vlan_tag = tp_vlan_tci & 0x0fff;

		if (pcapint_filter_with_aux_data(handle->fcode.bf_insns,
					      bp,
					      tp_len,
					      snaplen,
					      &aux_data) == 0)
			return 0;
	}

	if (!linux_check_direction(handle, sll))
		return 0;

	/* get required packet info from ring header */
	pcaphdr.ts.tv_sec = tp_sec;
	pcaphdr.ts.tv_usec = tp_usec;
	pcaphdr.caplen = tp_snaplen;
	pcaphdr.len = tp_len;

	/* if required build in place the sll header*/
	if (handlep->cooked) {
		/* update packet len */
		if (handle->linktype == DLT_LINUX_SLL2) {
			pcaphdr.caplen += SLL2_HDR_LEN;
			pcaphdr.len += SLL2_HDR_LEN;
		} else {
			pcaphdr.caplen += SLL_HDR_LEN;
			pcaphdr.len += SLL_HDR_LEN;
		}
	}

	if (tp_vlan_tci_valid &&
		handlep->vlan_offset != -1 &&
		tp_snaplen >= (unsigned int) handlep->vlan_offset)
	{
		struct vlan_tag *tag;

		/*
		 * Move everything in the header, except the type field,
		 * down VLAN_TAG_LEN bytes, to allow us to insert the
		 * VLAN tag between that stuff and the type field.
		 */
		bp -= VLAN_TAG_LEN;
		memmove(bp, bp + VLAN_TAG_LEN, handlep->vlan_offset);

		/*
		 * Now insert the tag.
		 */
		tag = (struct vlan_tag *)(bp + handlep->vlan_offset);
		tag->vlan_tpid = htons(tp_vlan_tpid);
		tag->vlan_tci = htons(tp_vlan_tci);

		/*
		 * Add the tag to the packet lengths.
		 */
		pcaphdr.caplen += VLAN_TAG_LEN;
		pcaphdr.len += VLAN_TAG_LEN;
	}

	/*
	 * The only way to tell the kernel to cut off the
	 * packet at a snapshot length is with a filter program;
	 * if there's no filter program, the kernel won't cut
	 * the packet off.
	 *
	 * Trim the snapshot length to be no longer than the
	 * specified snapshot length.
	 *
	 * XXX - an alternative is to put a filter, consisting
	 * of a "ret <snaplen>" instruction, on the socket
	 * in the activate routine, so that the truncation is
	 * done in the kernel even if nobody specified a filter;
	 * that means that less buffer space is consumed in
	 * the memory-mapped buffer.
	 */
	if (pcaphdr.caplen > (bpf_u_int32)handle->snapshot)
		pcaphdr.caplen = handle->snapshot;

	/* pass the packet to the user */
	callback(user, &pcaphdr, bp);

	return 1;
}

static int
pcap_read_linux_mmap_v2(pcap_t *handle, int max_packets, pcap_handler callback,
		u_char *user)
{
	struct pcap_linux *handlep = handle->priv;
	union thdr h;
	int pkts = 0;
	int ret;

	/* wait for frames availability.*/
	h.raw = RING_GET_CURRENT_FRAME(handle);
	if (!packet_mmap_acquire(h.h2)) {
		/*
		 * The current frame is owned by the kernel; wait for
		 * a frame to be handed to us.
		 */
		ret = pcap_wait_for_frames_mmap(handle);
		if (ret) {
			return ret;
		}
	}

	/*
	 * This can conceivably process more than INT_MAX packets,
	 * which would overflow the packet count, causing it either
	 * to look like a negative number, and thus cause us to
	 * return a value that looks like an error, or overflow
	 * back into positive territory, and thus cause us to
	 * return a too-low count.
	 *
	 * Therefore, if the packet count is unlimited, we clip
	 * it at INT_MAX; this routine is not expected to
	 * process packets indefinitely, so that's not an issue.
	 */
	if (PACKET_COUNT_IS_UNLIMITED(max_packets))
		max_packets = INT_MAX;

	while (pkts < max_packets) {
		/*
		 * Get the current ring buffer frame, and break if
		 * it's still owned by the kernel.
		 */
		h.raw = RING_GET_CURRENT_FRAME(handle);
		if (!packet_mmap_acquire(h.h2))
			break;

		ret = pcap_handle_packet_mmap(
				handle,
				callback,
				user,
				h.raw,
				h.h2->tp_len,
				h.h2->tp_mac,
				h.h2->tp_snaplen,
				h.h2->tp_sec,
				handle->opt.tstamp_precision == PCAP_TSTAMP_PRECISION_NANO ? h.h2->tp_nsec : h.h2->tp_nsec / 1000,
				VLAN_VALID(h.h2, h.h2),
				h.h2->tp_vlan_tci,
				VLAN_TPID(h.h2, h.h2));
		if (ret == 1) {
			pkts++;
		} else if (ret < 0) {
			return ret;
		}

		/*
		 * Hand this block back to the kernel, and, if we're
		 * counting blocks that need to be filtered in userland
		 * after having been filtered by the kernel, count
		 * the one we've just processed.
		 */
		packet_mmap_release(h.h2);
		if (handlep->blocks_to_filter_in_userland > 0) {
			handlep->blocks_to_filter_in_userland--;
			if (handlep->blocks_to_filter_in_userland == 0) {
				/*
				 * No more blocks need to be filtered
				 * in userland.
				 */
				handlep->filter_in_userland = 0;
			}
		}

		/* next block */
		if (++handle->offset >= handle->cc)
			handle->offset = 0;

		/* check for break loop condition*/
		if (handle->break_loop) {
			handle->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}
	}
	return pkts;
}

#ifdef HAVE_TPACKET3
static int
pcap_read_linux_mmap_v3(pcap_t *handle, int max_packets, pcap_handler callback,
		u_char *user)
{
	struct pcap_linux *handlep = handle->priv;
	union thdr h;
	int pkts = 0;
	int ret;

again:
	if (handlep->current_packet == NULL) {
		/* wait for frames availability.*/
		h.raw = RING_GET_CURRENT_FRAME(handle);
		if (!packet_mmap_v3_acquire(h.h3)) {
			/*
			 * The current frame is owned by the kernel; wait
			 * for a frame to be handed to us.
			 */
			ret = pcap_wait_for_frames_mmap(handle);
			if (ret) {
				return ret;
			}
		}
	}
	h.raw = RING_GET_CURRENT_FRAME(handle);
	if (!packet_mmap_v3_acquire(h.h3)) {
		if (pkts == 0 && handlep->timeout == 0) {
			/* Block until we see a packet. */
			goto again;
		}
		return pkts;
	}

	/*
	 * This can conceivably process more than INT_MAX packets,
	 * which would overflow the packet count, causing it either
	 * to look like a negative number, and thus cause us to
	 * return a value that looks like an error, or overflow
	 * back into positive territory, and thus cause us to
	 * return a too-low count.
	 *
	 * Therefore, if the packet count is unlimited, we clip
	 * it at INT_MAX; this routine is not expected to
	 * process packets indefinitely, so that's not an issue.
	 */
	if (PACKET_COUNT_IS_UNLIMITED(max_packets))
		max_packets = INT_MAX;

	while (pkts < max_packets) {
		int packets_to_read;

		if (handlep->current_packet == NULL) {
			h.raw = RING_GET_CURRENT_FRAME(handle);
			if (!packet_mmap_v3_acquire(h.h3))
				break;

			handlep->current_packet = h.raw + h.h3->hdr.bh1.offset_to_first_pkt;
			handlep->packets_left = h.h3->hdr.bh1.num_pkts;
		}
		packets_to_read = handlep->packets_left;

		if (packets_to_read > (max_packets - pkts)) {
			/*
			 * There are more packets in the buffer than
			 * the number of packets we have left to
			 * process to get up to the maximum number
			 * of packets to process.  Only process enough
			 * of them to get us up to that maximum.
			 */
			packets_to_read = max_packets - pkts;
		}

		while (packets_to_read-- && !handle->break_loop) {
			struct tpacket3_hdr* tp3_hdr = (struct tpacket3_hdr*) handlep->current_packet;
			ret = pcap_handle_packet_mmap(
					handle,
					callback,
					user,
					handlep->current_packet,
					tp3_hdr->tp_len,
					tp3_hdr->tp_mac,
					tp3_hdr->tp_snaplen,
					tp3_hdr->tp_sec,
					handle->opt.tstamp_precision == PCAP_TSTAMP_PRECISION_NANO ? tp3_hdr->tp_nsec : tp3_hdr->tp_nsec / 1000,
					VLAN_VALID(tp3_hdr, &tp3_hdr->hv1),
					tp3_hdr->hv1.tp_vlan_tci,
					VLAN_TPID(tp3_hdr, &tp3_hdr->hv1));
			if (ret == 1) {
				pkts++;
			} else if (ret < 0) {
				handlep->current_packet = NULL;
				return ret;
			}
			handlep->current_packet += tp3_hdr->tp_next_offset;
			handlep->packets_left--;
		}

		if (handlep->packets_left <= 0) {
			/*
			 * Hand this block back to the kernel, and, if
			 * we're counting blocks that need to be
			 * filtered in userland after having been
			 * filtered by the kernel, count the one we've
			 * just processed.
			 */
			packet_mmap_v3_release(h.h3);
			if (handlep->blocks_to_filter_in_userland > 0) {
				handlep->blocks_to_filter_in_userland--;
				if (handlep->blocks_to_filter_in_userland == 0) {
					/*
					 * No more blocks need to be filtered
					 * in userland.
					 */
					handlep->filter_in_userland = 0;
				}
			}

			/* next block */
			if (++handle->offset >= handle->cc)
				handle->offset = 0;

			handlep->current_packet = NULL;
		}

		/* check for break loop condition*/
		if (handle->break_loop) {
			handle->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}
	}
	if (pkts == 0 && handlep->timeout == 0) {
		/* Block until we see a packet. */
		goto again;
	}
	return pkts;
}
#endif /* HAVE_TPACKET3 */

/*
 *  Attach the given BPF code to the packet capture device.
 */
static int
pcap_setfilter_linux(pcap_t *handle, struct bpf_program *filter)
{
	struct pcap_linux *handlep;
	struct sock_fprog	fcode;
	int			can_filter_in_kernel;
	int			err = 0;
	int			n, offset;

	if (!handle)
		return -1;
	if (!filter) {
	        pcapint_strlcpy(handle->errbuf, "setfilter: No filter specified",
			PCAP_ERRBUF_SIZE);
		return -1;
	}

	handlep = handle->priv;

	/* Make our private copy of the filter */

	if (pcapint_install_bpf_program(handle, filter) < 0)
		/* pcapint_install_bpf_program() filled in errbuf */
		return -1;

	/*
	 * Run user level packet filter by default. Will be overridden if
	 * installing a kernel filter succeeds.
	 */
	handlep->filter_in_userland = 1;

	/* Install kernel level filter if possible */

#ifdef USHRT_MAX
	if (handle->fcode.bf_len > USHRT_MAX) {
		/*
		 * fcode.len is an unsigned short for current kernel.
		 * I have yet to see BPF-Code with that much
		 * instructions but still it is possible. So for the
		 * sake of correctness I added this check.
		 */
		fprintf(stderr, "Warning: Filter too complex for kernel\n");
		fcode.len = 0;
		fcode.filter = NULL;
		can_filter_in_kernel = 0;
	} else
#endif /* USHRT_MAX */
	{
		/*
		 * Oh joy, the Linux kernel uses struct sock_fprog instead
		 * of struct bpf_program and of course the length field is
		 * of different size. Pointed out by Sebastian
		 *
		 * Oh, and we also need to fix it up so that all "ret"
		 * instructions with non-zero operands have MAXIMUM_SNAPLEN
		 * as the operand if we're not capturing in memory-mapped
		 * mode, and so that, if we're in cooked mode, all memory-
		 * reference instructions use special magic offsets in
		 * references to the link-layer header and assume that the
		 * link-layer payload begins at 0; "fix_program()" will do
		 * that.
		 */
		switch (fix_program(handle, &fcode)) {

		case -1:
		default:
			/*
			 * Fatal error; just quit.
			 * (The "default" case shouldn't happen; we
			 * return -1 for that reason.)
			 */
			return -1;

		case 0:
			/*
			 * The program performed checks that we can't make
			 * work in the kernel.
			 */
			can_filter_in_kernel = 0;
			break;

		case 1:
			/*
			 * We have a filter that'll work in the kernel.
			 */
			can_filter_in_kernel = 1;
			break;
		}
	}

	/*
	 * NOTE: at this point, we've set both the "len" and "filter"
	 * fields of "fcode".  As of the 2.6.32.4 kernel, at least,
	 * those are the only members of the "sock_fprog" structure,
	 * so we initialize every member of that structure.
	 *
	 * If there is anything in "fcode" that is not initialized,
	 * it is either a field added in a later kernel, or it's
	 * padding.
	 *
	 * If a new field is added, this code needs to be updated
	 * to set it correctly.
	 *
	 * If there are no other fields, then:
	 *
	 *	if the Linux kernel looks at the padding, it's
	 *	buggy;
	 *
	 *	if the Linux kernel doesn't look at the padding,
	 *	then if some tool complains that we're passing
	 *	uninitialized data to the kernel, then the tool
	 *	is buggy and needs to understand that it's just
	 *	padding.
	 */
	if (can_filter_in_kernel) {
		if ((err = set_kernel_filter(handle, &fcode)) == 0)
		{
			/*
			 * Installation succeeded - using kernel filter,
			 * so userland filtering not needed.
			 */
			handlep->filter_in_userland = 0;
		}
		else if (err == -1)	/* Non-fatal error */
		{
			/*
			 * Print a warning if we weren't able to install
			 * the filter for a reason other than "this kernel
			 * isn't configured to support socket filters.
			 */
			if (errno == ENOMEM) {
				/*
				 * Either a kernel memory allocation
				 * failure occurred, or there's too
				 * much "other/option memory" allocated
				 * for this socket.  Suggest that they
				 * increase the "other/option memory"
				 * limit.
				 */
				fprintf(stderr,
				    "Warning: Couldn't allocate kernel memory for filter: try increasing net.core.optmem_max with sysctl\n");
			} else if (errno != ENOPROTOOPT && errno != EOPNOTSUPP) {
				fprintf(stderr,
				    "Warning: Kernel filter failed: %s\n",
					pcap_strerror(errno));
			}
		}
	}

	/*
	 * If we're not using the kernel filter, get rid of any kernel
	 * filter that might've been there before, e.g. because the
	 * previous filter could work in the kernel, or because some other
	 * code attached a filter to the socket by some means other than
	 * calling "pcap_setfilter()".  Otherwise, the kernel filter may
	 * filter out packets that would pass the new userland filter.
	 */
	if (handlep->filter_in_userland) {
		if (reset_kernel_filter(handle) == -1) {
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno,
			    "can't remove kernel filter");
			err = -2;	/* fatal error */
		}
	}

	/*
	 * Free up the copy of the filter that was made by "fix_program()".
	 */
	if (fcode.filter != NULL)
		free(fcode.filter);

	if (err == -2)
		/* Fatal error */
		return -1;

	/*
	 * If we're filtering in userland, there's nothing to do;
	 * the new filter will be used for the next packet.
	 */
	if (handlep->filter_in_userland)
		return 0;

	/*
	 * We're filtering in the kernel; the packets present in
	 * all blocks currently in the ring were already filtered
	 * by the old filter, and so will need to be filtered in
	 * userland by the new filter.
	 *
	 * Get an upper bound for the number of such blocks; first,
	 * walk the ring backward and count the free blocks.
	 */
	offset = handle->offset;
	if (--offset < 0)
		offset = handle->cc - 1;
	for (n=0; n < handle->cc; ++n) {
		if (--offset < 0)
			offset = handle->cc - 1;
		if (pcap_get_ring_frame_status(handle, offset) != TP_STATUS_KERNEL)
			break;
	}

	/*
	 * If we found free blocks, decrement the count of free
	 * blocks by 1, just in case we lost a race with another
	 * thread of control that was adding a packet while
	 * we were counting and that had run the filter before
	 * we changed it.
	 *
	 * XXX - could there be more than one block added in
	 * this fashion?
	 *
	 * XXX - is there a way to avoid that race, e.g. somehow
	 * wait for all packets that passed the old filter to
	 * be added to the ring?
	 */
	if (n != 0)
		n--;

	/*
	 * Set the count of blocks worth of packets to filter
	 * in userland to the total number of blocks in the
	 * ring minus the number of free blocks we found, and
	 * turn on userland filtering.  (The count of blocks
	 * worth of packets to filter in userland is guaranteed
	 * not to be zero - n, above, couldn't be set to a
	 * value > handle->cc, and if it were equal to
	 * handle->cc, it wouldn't be zero, and thus would
	 * be decremented to handle->cc - 1.)
	 */
	handlep->blocks_to_filter_in_userland = handle->cc - n;
	handlep->filter_in_userland = 1;

	return 0;
}

/*
 *  Return the index of the given device name. Fill ebuf and return
 *  -1 on failure.
 */
static int
iface_get_id(int fd, const char *device, char *ebuf)
{
	struct ifreq	ifr;

	memset(&ifr, 0, sizeof(ifr));
	pcapint_strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
		    errno, "SIOCGIFINDEX");
		return -1;
	}

	return ifr.ifr_ifindex;
}

/*
 *  Bind the socket associated with FD to the given device.
 *  Return 0 on success or a PCAP_ERROR_ value on a hard error.
 */
static int
iface_bind(int fd, int ifindex, char *ebuf, int protocol)
{
	struct sockaddr_ll	sll;
	int			ret, err;
	socklen_t		errlen = sizeof(err);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family		= AF_PACKET;
	sll.sll_ifindex		= ifindex < 0 ? 0 : ifindex;
	sll.sll_protocol	= protocol;

	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
		if (errno == ENETDOWN) {
			/*
			 * Return a "network down" indication, so that
			 * the application can report that rather than
			 * saying we had a mysterious failure and
			 * suggest that they report a problem to the
			 * libpcap developers.
			 */
			return PCAP_ERROR_IFACE_NOT_UP;
		}
		if (errno == ENODEV) {
			/*
			 * There's nothing more to say, so clear the
			 * error message.
			 */
			ebuf[0] = '\0';
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
		} else {
			ret = PCAP_ERROR;
			pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
			    errno, "bind");
		}
		return ret;
	}

	/* Any pending errors, e.g., network is down? */

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
		pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
		    errno, "getsockopt (SO_ERROR)");
		return PCAP_ERROR;
	}

	if (err == ENETDOWN) {
		/*
		 * Return a "network down" indication, so that
		 * the application can report that rather than
		 * saying we had a mysterious failure and
		 * suggest that they report a problem to the
		 * libpcap developers.
		 */
		return PCAP_ERROR_IFACE_NOT_UP;
	} else if (err > 0) {
		pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
		    err, "bind");
		return PCAP_ERROR;
	}

	return 0;
}

/*
 * Try to enter monitor mode.
 * If we have libnl, try to create a new monitor-mode device and
 * capture on that; otherwise, just say "not supported".
 */
#ifdef HAVE_LIBNL
static int
enter_rfmon_mode(pcap_t *handle, int sock_fd, const char *device)
{
	struct pcap_linux *handlep = handle->priv;
	int ret;
	char phydev_path[PATH_MAX+1];
	struct nl80211_state nlstate;
	struct ifreq ifr;
	u_int n;

	/*
	 * Is this a mac80211 device?
	 */
	ret = get_mac80211_phydev(handle, device, phydev_path, PATH_MAX);
	if (ret < 0)
		return ret;	/* error */
	if (ret == 0)
		return 0;	/* no error, but not mac80211 device */

	/*
	 * XXX - is this already a monN device?
	 * If so, we're done.
	 */

	/*
	 * OK, it's apparently a mac80211 device.
	 * Try to find an unused monN device for it.
	 */
	ret = nl80211_init(handle, &nlstate, device);
	if (ret != 0)
		return ret;
	for (n = 0; n < UINT_MAX; n++) {
		/*
		 * Try mon{n}.
		 */
		char mondevice[3+10+1];	/* mon{UINT_MAX}\0 */

		snprintf(mondevice, sizeof mondevice, "mon%u", n);
		ret = add_mon_if(handle, sock_fd, &nlstate, device, mondevice);
		if (ret == 1) {
			/*
			 * Success.  We don't clean up the libnl state
			 * yet, as we'll be using it later.
			 */
			goto added;
		}
		if (ret < 0) {
			/*
			 * Hard failure.  Just return ret; handle->errbuf
			 * has already been set.
			 */
			nl80211_cleanup(&nlstate);
			return ret;
		}
	}

	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
	    "%s: No free monN interfaces", device);
	nl80211_cleanup(&nlstate);
	return PCAP_ERROR;

added:

#if 0
	/*
	 * Sleep for .1 seconds.
	 */
	delay.tv_sec = 0;
	delay.tv_nsec = 500000000;
	nanosleep(&delay, NULL);
#endif

	/*
	 * If we haven't already done so, arrange to have
	 * "pcap_close_all()" called when we exit.
	 */
	if (!pcapint_do_addexit(handle)) {
		/*
		 * "atexit()" failed; don't put the interface
		 * in rfmon mode, just give up.
		 */
		del_mon_if(handle, sock_fd, &nlstate, device,
		    handlep->mondevice);
		nl80211_cleanup(&nlstate);
		return PCAP_ERROR;
	}

	/*
	 * Now configure the monitor interface up.
	 */
	memset(&ifr, 0, sizeof(ifr));
	pcapint_strlcpy(ifr.ifr_name, handlep->mondevice, sizeof(ifr.ifr_name));
	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "%s: Can't get flags for %s", device,
		    handlep->mondevice);
		del_mon_if(handle, sock_fd, &nlstate, device,
		    handlep->mondevice);
		nl80211_cleanup(&nlstate);
		return PCAP_ERROR;
	}
	ifr.ifr_flags |= IFF_UP|IFF_RUNNING;
	if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "%s: Can't set flags for %s", device,
		    handlep->mondevice);
		del_mon_if(handle, sock_fd, &nlstate, device,
		    handlep->mondevice);
		nl80211_cleanup(&nlstate);
		return PCAP_ERROR;
	}

	/*
	 * Success.  Clean up the libnl state.
	 */
	nl80211_cleanup(&nlstate);

	/*
	 * Note that we have to delete the monitor device when we close
	 * the handle.
	 */
	handlep->must_do_on_close |= MUST_DELETE_MONIF;

	/*
	 * Add this to the list of pcaps to close when we exit.
	 */
	pcapint_add_to_pcaps_to_close(handle);

	return 1;
}
#else /* HAVE_LIBNL */
static int
enter_rfmon_mode(pcap_t *handle _U_, int sock_fd _U_, const char *device _U_)
{
	/*
	 * We don't have libnl, so we can't do monitor mode.
	 */
	return 0;
}
#endif /* HAVE_LIBNL */

#if defined(HAVE_LINUX_NET_TSTAMP_H) && defined(PACKET_TIMESTAMP)
/*
 * Map SOF_TIMESTAMPING_ values to PCAP_TSTAMP_ values.
 */
static const struct {
	int soft_timestamping_val;
	int pcap_tstamp_val;
} sof_ts_type_map[3] = {
	{ SOF_TIMESTAMPING_SOFTWARE, PCAP_TSTAMP_HOST },
	{ SOF_TIMESTAMPING_SYS_HARDWARE, PCAP_TSTAMP_ADAPTER },
	{ SOF_TIMESTAMPING_RAW_HARDWARE, PCAP_TSTAMP_ADAPTER_UNSYNCED }
};
#define NUM_SOF_TIMESTAMPING_TYPES	(sizeof sof_ts_type_map / sizeof sof_ts_type_map[0])

/*
 * Set the list of time stamping types to include all types.
 */
static int
iface_set_all_ts_types(pcap_t *handle, char *ebuf)
{
	u_int i;

	handle->tstamp_type_list = malloc(NUM_SOF_TIMESTAMPING_TYPES * sizeof(u_int));
	if (handle->tstamp_type_list == NULL) {
		pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		return -1;
	}
	for (i = 0; i < NUM_SOF_TIMESTAMPING_TYPES; i++)
		handle->tstamp_type_list[i] = sof_ts_type_map[i].pcap_tstamp_val;
	handle->tstamp_type_count = NUM_SOF_TIMESTAMPING_TYPES;
	return 0;
}

/*
 * Get a list of time stamp types.
 */
#ifdef ETHTOOL_GET_TS_INFO
static int
iface_get_ts_types(const char *device, pcap_t *handle, char *ebuf)
{
	int fd;
	struct ifreq ifr;
	struct ethtool_ts_info info;
	int num_ts_types;
	u_int i, j;

	/*
	 * This doesn't apply to the "any" device; you can't say "turn on
	 * hardware time stamping for all devices that exist now and arrange
	 * that it be turned on for any device that appears in the future",
	 * and not all devices even necessarily *support* hardware time
	 * stamping, so don't report any time stamp types.
	 */
	if (strcmp(device, "any") == 0) {
		handle->tstamp_type_list = NULL;
		return 0;
	}

	/*
	 * Create a socket from which to fetch time stamping capabilities.
	 */
	fd = get_if_ioctl_socket();
	if (fd < 0) {
		pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
		    errno, "socket for SIOCETHTOOL(ETHTOOL_GET_TS_INFO)");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	pcapint_strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	memset(&info, 0, sizeof(info));
	info.cmd = ETHTOOL_GET_TS_INFO;
	ifr.ifr_data = (caddr_t)&info;
	if (ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
		int save_errno = errno;

		close(fd);
		switch (save_errno) {

		case EOPNOTSUPP:
		case EINVAL:
			/*
			 * OK, this OS version or driver doesn't support
			 * asking for the time stamping types, so let's
			 * just return all the possible types.
			 */
			if (iface_set_all_ts_types(handle, ebuf) == -1)
				return -1;
			return 0;

		case ENODEV:
			/*
			 * OK, no such device.
			 * The user will find that out when they try to
			 * activate the device; just return an empty
			 * list of time stamp types.
			 */
			handle->tstamp_type_list = NULL;
			return 0;

		default:
			/*
			 * Other error.
			 */
			pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
			    save_errno,
			    "%s: SIOCETHTOOL(ETHTOOL_GET_TS_INFO) ioctl failed",
			    device);
			return -1;
		}
	}
	close(fd);

	/*
	 * Do we support hardware time stamping of *all* packets?
	 */
	if (!(info.rx_filters & (1 << HWTSTAMP_FILTER_ALL))) {
		/*
		 * No, so don't report any time stamp types.
		 *
		 * XXX - some devices either don't report
		 * HWTSTAMP_FILTER_ALL when they do support it, or
		 * report HWTSTAMP_FILTER_ALL but map it to only
		 * time stamping a few PTP packets.  See
		 * http://marc.info/?l=linux-netdev&m=146318183529571&w=2
		 *
		 * Maybe that got fixed later.
		 */
		handle->tstamp_type_list = NULL;
		return 0;
	}

	num_ts_types = 0;
	for (i = 0; i < NUM_SOF_TIMESTAMPING_TYPES; i++) {
		if (info.so_timestamping & sof_ts_type_map[i].soft_timestamping_val)
			num_ts_types++;
	}
	if (num_ts_types != 0) {
		handle->tstamp_type_list = malloc(num_ts_types * sizeof(u_int));
		if (handle->tstamp_type_list == NULL) {
			pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
			    errno, "malloc");
			return -1;
		}
		for (i = 0, j = 0; i < NUM_SOF_TIMESTAMPING_TYPES; i++) {
			if (info.so_timestamping & sof_ts_type_map[i].soft_timestamping_val) {
				handle->tstamp_type_list[j] = sof_ts_type_map[i].pcap_tstamp_val;
				j++;
			}
		}
		handle->tstamp_type_count = num_ts_types;
	} else
		handle->tstamp_type_list = NULL;

	return 0;
}
#else /* ETHTOOL_GET_TS_INFO */
static int
iface_get_ts_types(const char *device, pcap_t *handle, char *ebuf)
{
	/*
	 * This doesn't apply to the "any" device; you can't say "turn on
	 * hardware time stamping for all devices that exist now and arrange
	 * that it be turned on for any device that appears in the future",
	 * and not all devices even necessarily *support* hardware time
	 * stamping, so don't report any time stamp types.
	 */
	if (strcmp(device, "any") == 0) {
		handle->tstamp_type_list = NULL;
		return 0;
	}

	/*
	 * We don't have an ioctl to use to ask what's supported,
	 * so say we support everything.
	 */
	if (iface_set_all_ts_types(handle, ebuf) == -1)
		return -1;
	return 0;
}
#endif /* ETHTOOL_GET_TS_INFO */
#else  /* defined(HAVE_LINUX_NET_TSTAMP_H) && defined(PACKET_TIMESTAMP) */
static int
iface_get_ts_types(const char *device _U_, pcap_t *p _U_, char *ebuf _U_)
{
	/*
	 * Nothing to fetch, so it always "succeeds".
	 */
	return 0;
}
#endif /* defined(HAVE_LINUX_NET_TSTAMP_H) && defined(PACKET_TIMESTAMP) */

/*
 * Find out if we have any form of fragmentation/reassembly offloading.
 *
 * We do so using SIOCETHTOOL checking for various types of offloading;
 * if SIOCETHTOOL isn't defined, or we don't have any #defines for any
 * of the types of offloading, there's nothing we can do to check, so
 * we just say "no, we don't".
 *
 * We treat EOPNOTSUPP, EINVAL and, if eperm_ok is true, EPERM as
 * indications that the operation isn't supported.  We do EPERM
 * weirdly because the SIOCETHTOOL code in later kernels 1) doesn't
 * support ETHTOOL_GUFO, 2) also doesn't include it in the list
 * of ethtool operations that don't require CAP_NET_ADMIN privileges,
 * and 3) does the "is this permitted" check before doing the "is
 * this even supported" check, so it fails with "this is not permitted"
 * rather than "this is not even supported".  To work around this
 * annoyance, we only treat EPERM as an error for the first feature,
 * and assume that they all do the same permission checks, so if the
 * first one is allowed all the others are allowed if supported.
 */
#if defined(SIOCETHTOOL) && (defined(ETHTOOL_GTSO) || defined(ETHTOOL_GUFO) || defined(ETHTOOL_GGSO) || defined(ETHTOOL_GFLAGS) || defined(ETHTOOL_GGRO))
static int
iface_ethtool_flag_ioctl(pcap_t *handle, int cmd, const char *cmdname,
    int eperm_ok)
{
	struct ifreq	ifr;
	struct ethtool_value eval;

	memset(&ifr, 0, sizeof(ifr));
	pcapint_strlcpy(ifr.ifr_name, handle->opt.device, sizeof(ifr.ifr_name));
	eval.cmd = cmd;
	eval.data = 0;
	ifr.ifr_data = (caddr_t)&eval;
	if (ioctl(handle->fd, SIOCETHTOOL, &ifr) == -1) {
		if (errno == EOPNOTSUPP || errno == EINVAL ||
		    (errno == EPERM && eperm_ok)) {
			/*
			 * OK, let's just return 0, which, in our
			 * case, either means "no, what we're asking
			 * about is not enabled" or "all the flags
			 * are clear (i.e., nothing is enabled)".
			 */
			return 0;
		}
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "%s: SIOCETHTOOL(%s) ioctl failed",
		    handle->opt.device, cmdname);
		return -1;
	}
	return eval.data;
}

/*
 * XXX - it's annoying that we have to check for offloading at all, but,
 * given that we have to, it's still annoying that we have to check for
 * particular types of offloading, especially that shiny new types of
 * offloading may be added - and, worse, may not be checkable with
 * a particular ETHTOOL_ operation; ETHTOOL_GFEATURES would, in
 * theory, give those to you, but the actual flags being used are
 * opaque (defined in a non-uapi header), and there doesn't seem to
 * be any obvious way to ask the kernel what all the offloading flags
 * are - at best, you can ask for a set of strings(!) to get *names*
 * for various flags.  (That whole mechanism appears to have been
 * designed for the sole purpose of letting ethtool report flags
 * by name and set flags by name, with the names having no semantics
 * ethtool understands.)
 */
static int
iface_get_offload(pcap_t *handle)
{
	int ret;

#ifdef ETHTOOL_GTSO
	ret = iface_ethtool_flag_ioctl(handle, ETHTOOL_GTSO, "ETHTOOL_GTSO", 0);
	if (ret == -1)
		return -1;
	if (ret)
		return 1;	/* TCP segmentation offloading on */
#endif

#ifdef ETHTOOL_GGSO
	/*
	 * XXX - will this cause large unsegmented packets to be
	 * handed to PF_PACKET sockets on transmission?  If not,
	 * this need not be checked.
	 */
	ret = iface_ethtool_flag_ioctl(handle, ETHTOOL_GGSO, "ETHTOOL_GGSO", 0);
	if (ret == -1)
		return -1;
	if (ret)
		return 1;	/* generic segmentation offloading on */
#endif

#ifdef ETHTOOL_GFLAGS
	ret = iface_ethtool_flag_ioctl(handle, ETHTOOL_GFLAGS, "ETHTOOL_GFLAGS", 0);
	if (ret == -1)
		return -1;
	if (ret & ETH_FLAG_LRO)
		return 1;	/* large receive offloading on */
#endif

#ifdef ETHTOOL_GGRO
	/*
	 * XXX - will this cause large reassembled packets to be
	 * handed to PF_PACKET sockets on receipt?  If not,
	 * this need not be checked.
	 */
	ret = iface_ethtool_flag_ioctl(handle, ETHTOOL_GGRO, "ETHTOOL_GGRO", 0);
	if (ret == -1)
		return -1;
	if (ret)
		return 1;	/* generic (large) receive offloading on */
#endif

#ifdef ETHTOOL_GUFO
	/*
	 * Do this one last, as support for it was removed in later
	 * kernels, and it fails with EPERM on those kernels rather
	 * than with EOPNOTSUPP (see explanation in comment for
	 * iface_ethtool_flag_ioctl()).
	 */
	ret = iface_ethtool_flag_ioctl(handle, ETHTOOL_GUFO, "ETHTOOL_GUFO", 1);
	if (ret == -1)
		return -1;
	if (ret)
		return 1;	/* UDP fragmentation offloading on */
#endif

	return 0;
}
#else /* SIOCETHTOOL */
static int
iface_get_offload(pcap_t *handle _U_)
{
	/*
	 * XXX - do we need to get this information if we don't
	 * have the ethtool ioctls?  If so, how do we do that?
	 */
	return 0;
}
#endif /* SIOCETHTOOL */

static struct dsa_proto {
	const char *name;
	bpf_u_int32 linktype;
} dsa_protos[] = {
	/*
	 * None is special and indicates that the interface does not have
	 * any tagging protocol configured, and is therefore a standard
	 * Ethernet interface.
	 */
	{ "none", DLT_EN10MB },
	{ "brcm", DLT_DSA_TAG_BRCM },
	{ "brcm-prepend", DLT_DSA_TAG_BRCM_PREPEND },
	{ "dsa", DLT_DSA_TAG_DSA },
	{ "edsa", DLT_DSA_TAG_EDSA },
};

static int
iface_dsa_get_proto_info(const char *device, pcap_t *handle)
{
	char *pathstr;
	unsigned int i;
	/*
	 * Make this significantly smaller than PCAP_ERRBUF_SIZE;
	 * the tag *shouldn't* have some huge long name, and making
	 * it smaller keeps newer versions of GCC from whining that
	 * the error message if we don't support the tag could
	 * overflow the error message buffer.
	 */
	char buf[128];
	ssize_t r;
	int fd;

	fd = asprintf(&pathstr, "/sys/class/net/%s/dsa/tagging", device);
	if (fd < 0) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
					  fd, "asprintf");
		return PCAP_ERROR;
	}

	fd = open(pathstr, O_RDONLY);
	free(pathstr);
	/*
	 * This is not fatal, kernel >= 4.20 *might* expose this attribute
	 */
	if (fd < 0)
		return 0;

	r = read(fd, buf, sizeof(buf) - 1);
	if (r <= 0) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
					  errno, "read");
		close(fd);
		return PCAP_ERROR;
	}
	close(fd);

	/*
	 * Buffer should be LF terminated.
	 */
	if (buf[r - 1] == '\n')
		r--;
	buf[r] = '\0';

	for (i = 0; i < sizeof(dsa_protos) / sizeof(dsa_protos[0]); i++) {
		if (strlen(dsa_protos[i].name) == (size_t)r &&
		    strcmp(buf, dsa_protos[i].name) == 0) {
			handle->linktype = dsa_protos[i].linktype;
			switch (dsa_protos[i].linktype) {
			case DLT_EN10MB:
				return 0;
			default:
				return 1;
			}
		}
	}

	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		      "unsupported DSA tag: %s", buf);

	return PCAP_ERROR;
}

/*
 *  Query the kernel for the MTU of the given interface.
 */
static int
iface_get_mtu(int fd, const char *device, char *ebuf)
{
	struct ifreq	ifr;

	if (!device)
		return BIGGER_THAN_ALL_MTUS;

	memset(&ifr, 0, sizeof(ifr));
	pcapint_strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFMTU, &ifr) == -1) {
		pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
		    errno, "SIOCGIFMTU");
		return -1;
	}

	return ifr.ifr_mtu;
}

/*
 *  Get the hardware type of the given interface as ARPHRD_xxx constant.
 */
static int
iface_get_arptype(int fd, const char *device, char *ebuf)
{
	struct ifreq	ifr;
	int		ret;

	memset(&ifr, 0, sizeof(ifr));
	pcapint_strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		if (errno == ENODEV) {
			/*
			 * No such device.
			 *
			 * There's nothing more to say, so clear
			 * the error message.
			 */
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
			ebuf[0] = '\0';
		} else {
			ret = PCAP_ERROR;
			pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
			    errno, "SIOCGIFHWADDR");
		}
		return ret;
	}

	return ifr.ifr_hwaddr.sa_family;
}

static int
fix_program(pcap_t *handle, struct sock_fprog *fcode)
{
	struct pcap_linux *handlep = handle->priv;
	size_t prog_size;
	register int i;
	register struct bpf_insn *p;
	struct bpf_insn *f;
	int len;

	/*
	 * Make a copy of the filter, and modify that copy if
	 * necessary.
	 */
	prog_size = sizeof(*handle->fcode.bf_insns) * handle->fcode.bf_len;
	len = handle->fcode.bf_len;
	f = (struct bpf_insn *)malloc(prog_size);
	if (f == NULL) {
		pcapint_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		return -1;
	}
	memcpy(f, handle->fcode.bf_insns, prog_size);
	fcode->len = len;
	fcode->filter = (struct sock_filter *) f;

	for (i = 0; i < len; ++i) {
		p = &f[i];
		/*
		 * What type of instruction is this?
		 */
		switch (BPF_CLASS(p->code)) {

		case BPF_LD:
		case BPF_LDX:
			/*
			 * It's a load instruction; is it loading
			 * from the packet?
			 */
			switch (BPF_MODE(p->code)) {

			case BPF_ABS:
			case BPF_IND:
			case BPF_MSH:
				/*
				 * Yes; are we in cooked mode?
				 */
				if (handlep->cooked) {
					/*
					 * Yes, so we need to fix this
					 * instruction.
					 */
					if (fix_offset(handle, p) < 0) {
						/*
						 * We failed to do so.
						 * Return 0, so our caller
						 * knows to punt to userland.
						 */
						return 0;
					}
				}
				break;
			}
			break;
		}
	}
	return 1;	/* we succeeded */
}

static int
fix_offset(pcap_t *handle, struct bpf_insn *p)
{
	/*
	 * Existing references to auxiliary data shouldn't be adjusted.
	 *
	 * Note that SKF_AD_OFF is negative, but p->k is unsigned, so
	 * we use >= and cast SKF_AD_OFF to unsigned.
	 */
	if (p->k >= (bpf_u_int32)SKF_AD_OFF)
		return 0;
	if (handle->linktype == DLT_LINUX_SLL2) {
		/*
		 * What's the offset?
		 */
		if (p->k >= SLL2_HDR_LEN) {
			/*
			 * It's within the link-layer payload; that starts
			 * at an offset of 0, as far as the kernel packet
			 * filter is concerned, so subtract the length of
			 * the link-layer header.
			 */
			p->k -= SLL2_HDR_LEN;
		} else if (p->k == 0) {
			/*
			 * It's the protocol field; map it to the
			 * special magic kernel offset for that field.
			 */
			p->k = SKF_AD_OFF + SKF_AD_PROTOCOL;
		} else if (p->k == 4) {
			/*
			 * It's the ifindex field; map it to the
			 * special magic kernel offset for that field.
			 */
			p->k = SKF_AD_OFF + SKF_AD_IFINDEX;
		} else if (p->k == 10) {
			/*
			 * It's the packet type field; map it to the
			 * special magic kernel offset for that field.
			 */
			p->k = SKF_AD_OFF + SKF_AD_PKTTYPE;
		} else if ((bpf_int32)(p->k) > 0) {
			/*
			 * It's within the header, but it's not one of
			 * those fields; we can't do that in the kernel,
			 * so punt to userland.
			 */
			return -1;
		}
	} else {
		/*
		 * What's the offset?
		 */
		if (p->k >= SLL_HDR_LEN) {
			/*
			 * It's within the link-layer payload; that starts
			 * at an offset of 0, as far as the kernel packet
			 * filter is concerned, so subtract the length of
			 * the link-layer header.
			 */
			p->k -= SLL_HDR_LEN;
		} else if (p->k == 0) {
			/*
			 * It's the packet type field; map it to the
			 * special magic kernel offset for that field.
			 */
			p->k = SKF_AD_OFF + SKF_AD_PKTTYPE;
		} else if (p->k == 14) {
			/*
			 * It's the protocol field; map it to the
			 * special magic kernel offset for that field.
			 */
			p->k = SKF_AD_OFF + SKF_AD_PROTOCOL;
		} else if ((bpf_int32)(p->k) > 0) {
			/*
			 * It's within the header, but it's not one of
			 * those fields; we can't do that in the kernel,
			 * so punt to userland.
			 */
			return -1;
		}
	}
	return 0;
}

static int
set_kernel_filter(pcap_t *handle, struct sock_fprog *fcode)
{
	int total_filter_on = 0;
	int save_mode;
	int ret;
	int save_errno;

	/*
	 * The socket filter code doesn't discard all packets queued
	 * up on the socket when the filter is changed; this means
	 * that packets that don't match the new filter may show up
	 * after the new filter is put onto the socket, if those
	 * packets haven't yet been read.
	 *
	 * This means, for example, that if you do a tcpdump capture
	 * with a filter, the first few packets in the capture might
	 * be packets that wouldn't have passed the filter.
	 *
	 * We therefore discard all packets queued up on the socket
	 * when setting a kernel filter.  (This isn't an issue for
	 * userland filters, as the userland filtering is done after
	 * packets are queued up.)
	 *
	 * To flush those packets, we put the socket in read-only mode,
	 * and read packets from the socket until there are no more to
	 * read.
	 *
	 * In order to keep that from being an infinite loop - i.e.,
	 * to keep more packets from arriving while we're draining
	 * the queue - we put the "total filter", which is a filter
	 * that rejects all packets, onto the socket before draining
	 * the queue.
	 *
	 * This code deliberately ignores any errors, so that you may
	 * get bogus packets if an error occurs, rather than having
	 * the filtering done in userland even if it could have been
	 * done in the kernel.
	 */
	if (setsockopt(handle->fd, SOL_SOCKET, SO_ATTACH_FILTER,
		       &total_fcode, sizeof(total_fcode)) == 0) {
		char drain[1];

		/*
		 * Note that we've put the total filter onto the socket.
		 */
		total_filter_on = 1;

		/*
		 * Save the socket's current mode, and put it in
		 * non-blocking mode; we drain it by reading packets
		 * until we get an error (which is normally a
		 * "nothing more to be read" error).
		 */
		save_mode = fcntl(handle->fd, F_GETFL, 0);
		if (save_mode == -1) {
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno,
			    "can't get FD flags when changing filter");
			return -2;
		}
		if (fcntl(handle->fd, F_SETFL, save_mode | O_NONBLOCK) < 0) {
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno,
			    "can't set nonblocking mode when changing filter");
			return -2;
		}
		while (recv(handle->fd, &drain, sizeof drain, MSG_TRUNC) >= 0)
			;
		save_errno = errno;
		if (save_errno != EAGAIN) {
			/*
			 * Fatal error.
			 *
			 * If we can't restore the mode or reset the
			 * kernel filter, there's nothing we can do.
			 */
			(void)fcntl(handle->fd, F_SETFL, save_mode);
			(void)reset_kernel_filter(handle);
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, save_errno,
			    "recv failed when changing filter");
			return -2;
		}
		if (fcntl(handle->fd, F_SETFL, save_mode) == -1) {
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno,
			    "can't restore FD flags when changing filter");
			return -2;
		}
	}

	/*
	 * Now attach the new filter.
	 */
	ret = setsockopt(handle->fd, SOL_SOCKET, SO_ATTACH_FILTER,
			 fcode, sizeof(*fcode));
	if (ret == -1 && total_filter_on) {
		/*
		 * Well, we couldn't set that filter on the socket,
		 * but we could set the total filter on the socket.
		 *
		 * This could, for example, mean that the filter was
		 * too big to put into the kernel, so we'll have to
		 * filter in userland; in any case, we'll be doing
		 * filtering in userland, so we need to remove the
		 * total filter so we see packets.
		 */
		save_errno = errno;

		/*
		 * If this fails, we're really screwed; we have the
		 * total filter on the socket, and it won't come off.
		 * Report it as a fatal error.
		 */
		if (reset_kernel_filter(handle) == -1) {
			pcapint_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno,
			    "can't remove kernel total filter");
			return -2;	/* fatal error */
		}

		errno = save_errno;
	}
	return ret;
}

static int
reset_kernel_filter(pcap_t *handle)
{
	int ret;
	/*
	 * setsockopt() barfs unless it get a dummy parameter.
	 * valgrind whines unless the value is initialized,
	 * as it has no idea that setsockopt() ignores its
	 * parameter.
	 */
	int dummy = 0;

	ret = setsockopt(handle->fd, SOL_SOCKET, SO_DETACH_FILTER,
				   &dummy, sizeof(dummy));
	/*
	 * Ignore ENOENT - it means "we don't have a filter", so there
	 * was no filter to remove, and there's still no filter.
	 *
	 * Also ignore ENONET, as a lot of kernel versions had a
	 * typo where ENONET, rather than ENOENT, was returned.
	 */
	if (ret == -1 && errno != ENOENT && errno != ENONET)
		return -1;
	return 0;
}

int
pcap_set_protocol_linux(pcap_t *p, int protocol)
{
	if (pcapint_check_activated(p))
		return (PCAP_ERROR_ACTIVATED);
	p->opt.protocol = protocol;
	return (0);
}

/*
 * Libpcap version string.
 */
const char *
pcap_lib_version(void)
{
#if defined(HAVE_TPACKET3)
	return (PCAP_VERSION_STRING " (with TPACKET_V3)");
#else
	return (PCAP_VERSION_STRING " (with TPACKET_V2)");
#endif
}
