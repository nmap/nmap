/*
 * Copyright (c) 1994, 1995, 1996
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
 *
 * @(#) $Header: /tcpdump/master/libpcap/pcap-int.h,v 1.94 2008-09-16 00:20:23 guy Exp $ (LBL)
 */

#ifndef pcap_int_h
#define	pcap_int_h

#include <pcap/pcap.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_LIBDLPI
#include <libdlpi.h>
#endif

#ifdef WIN32
#include <Packet32.h>
extern CRITICAL_SECTION g_PcapCompileCriticalSection;
#endif /* WIN32 */

#ifdef MSDOS
#include <fcntl.h>
#include <io.h>
#endif

#ifdef HAVE_SNF_API
#include <snf.h>
#endif

#if (defined(_MSC_VER) && (_MSC_VER <= 1200)) /* we are compiling with Visual Studio 6, that doesn't support the LL suffix*/

/*
 * Swap byte ordering of unsigned long long timestamp on a big endian
 * machine.
 */
#define SWAPLL(ull)  ((ull & 0xff00000000000000) >> 56) | \
                      ((ull & 0x00ff000000000000) >> 40) | \
                      ((ull & 0x0000ff0000000000) >> 24) | \
                      ((ull & 0x000000ff00000000) >> 8)  | \
                      ((ull & 0x00000000ff000000) << 8)  | \
                      ((ull & 0x0000000000ff0000) << 24) | \
                      ((ull & 0x000000000000ff00) << 40) | \
                      ((ull & 0x00000000000000ff) << 56)

#else /* A recent Visual studio compiler or not VC */

/*
 * Swap byte ordering of unsigned long long timestamp on a big endian
 * machine.
 */
#define SWAPLL(ull)  ((ull & 0xff00000000000000LL) >> 56) | \
                      ((ull & 0x00ff000000000000LL) >> 40) | \
                      ((ull & 0x0000ff0000000000LL) >> 24) | \
                      ((ull & 0x000000ff00000000LL) >> 8)  | \
                      ((ull & 0x00000000ff000000LL) << 8)  | \
                      ((ull & 0x0000000000ff0000LL) << 24) | \
                      ((ull & 0x000000000000ff00LL) << 40) | \
                      ((ull & 0x00000000000000ffLL) << 56)

#endif /* _MSC_VER */

/*
 * Savefile
 */
typedef enum {
	NOT_SWAPPED,
	SWAPPED,
	MAYBE_SWAPPED
} swapped_type_t;

/*
 * Used when reading a savefile.
 */
struct pcap_sf {
	FILE *rfile;
	int (*next_packet_op)(pcap_t *, struct pcap_pkthdr *, u_char **);
	int swapped;
	size_t hdrsize;
	swapped_type_t lengths_swapped;
	int version_major;
	int version_minor;
	bpf_u_int32 ifcount;	/* number of interfaces seen in this capture */
	u_int tsresol;		/* time stamp resolution */
	u_int tsscale;		/* scaling factor for resolution -> microseconds */
	u_int64_t tsoffset;	/* time stamp offset */
};

/*
 * Used when doing a live capture.
 */
struct pcap_md {
	struct pcap_stat stat;
	/*XXX*/
	int use_bpf;		/* using kernel filter */
	u_long	TotPkts;	/* can't oflow for 79 hrs on ether */
	u_long	TotAccepted;	/* count accepted by filter */
	u_long	TotDrops;	/* count of dropped packets */
	long	TotMissed;	/* missed by i/f during this run */
	long	OrigMissed;	/* missed by i/f before this run */
	char	*device;	/* device name */
	int	timeout;	/* timeout for buffering */
	int	must_do_on_close; /* stuff we must do when we close */
	struct pcap *next;	/* list of open pcaps that need stuff cleared on close */
#ifdef linux
	int	sock_packet;	/* using Linux 2.0 compatible interface */
	int	cooked;		/* using SOCK_DGRAM rather than SOCK_RAW */
	int	ifindex;	/* interface index of device we're bound to */
	int	lo_ifindex;	/* interface index of the loopback device */
	u_int	packets_read;	/* count of packets read with recvfrom() */
	bpf_u_int32 oldmode;	/* mode to restore when turning monitor mode off */
	char	*mondevice;	/* mac80211 monitor device we created */
	u_char	*mmapbuf;	/* memory-mapped region pointer */
	size_t	mmapbuflen;	/* size of region */
	u_int	tp_version;	/* version of tpacket_hdr for mmaped ring */
	u_int	tp_hdrlen;	/* hdrlen of tpacket_hdr for mmaped ring */
	u_char	*oneshot_buffer; /* buffer for copy of packet */
	long	proc_dropped; /* packets reported dropped by /proc/net/dev */
#endif /* linux */

#ifdef HAVE_DAG_API
#ifdef HAVE_DAG_STREAMS_API
	u_char	*dag_mem_bottom;	/* DAG card current memory bottom pointer */
	u_char	*dag_mem_top;	/* DAG card current memory top pointer */
#else /* HAVE_DAG_STREAMS_API */
	void	*dag_mem_base;	/* DAG card memory base address */
	u_int	dag_mem_bottom;	/* DAG card current memory bottom offset */
	u_int	dag_mem_top;	/* DAG card current memory top offset */
#endif /* HAVE_DAG_STREAMS_API */
	int	dag_fcs_bits;	/* Number of checksum bits from link layer */
	int	dag_offset_flags; /* Flags to pass to dag_offset(). */
	int	dag_stream;	/* DAG stream number */
	int	dag_timeout;	/* timeout specified to pcap_open_live.
				 * Same as in linux above, introduce
				 * generally? */
#endif /* HAVE_DAG_API */
#ifdef HAVE_SNF_API
	snf_handle_t snf_handle; /* opaque device handle */
	snf_ring_t   snf_ring;   /* opaque device ring handle */
        int          snf_timeout;
        int          snf_boardnum;
#endif /*HAVE_SNF_API*/

#ifdef HAVE_ZEROCOPY_BPF
       /*
        * Zero-copy read buffer -- for zero-copy BPF.  'buffer' above will
        * alternative between these two actual mmap'd buffers as required.
        * As there is a header on the front size of the mmap'd buffer, only
        * some of the buffer is exposed to libpcap as a whole via bufsize;
        * zbufsize is the true size.  zbuffer tracks the current zbuf
        * assocated with buffer so that it can be used to decide which the
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
#endif /* HAVE_ZEROCOPY_BPF */
};

/*
 * Stuff to do when we close.
 */
#define MUST_CLEAR_PROMISC	0x00000001	/* clear promiscuous mode */
#define MUST_CLEAR_RFMON	0x00000002	/* clear rfmon (monitor) mode */
#define MUST_DELETE_MONIF	0x00000004	/* delete monitor-mode interface */

struct pcap_opt {
	int	buffer_size;
	char	*source;
	int	promisc;
	int	rfmon;
};

/*
 * Ultrix, DEC OSF/1^H^H^H^H^H^H^H^H^HDigital UNIX^H^H^H^H^H^H^H^H^H^H^H^H
 * Tru64 UNIX, and some versions of NetBSD pad FDDI packets to make everything
 * line up on a nice boundary.
 */
#ifdef __NetBSD__
#include <sys/param.h>	/* needed to declare __NetBSD_Version__ */
#endif

#if defined(ultrix) || defined(__osf__) || (defined(__NetBSD__) && __NetBSD_Version__ > 106000000)
#define       PCAP_FDDIPAD 3
#endif

typedef int	(*activate_op_t)(pcap_t *);
typedef int	(*can_set_rfmon_op_t)(pcap_t *);
typedef int	(*read_op_t)(pcap_t *, int cnt, pcap_handler, u_char *);
typedef int	(*inject_op_t)(pcap_t *, const void *, size_t);
typedef int	(*setfilter_op_t)(pcap_t *, struct bpf_program *);
typedef int	(*setdirection_op_t)(pcap_t *, pcap_direction_t);
typedef int	(*set_datalink_op_t)(pcap_t *, int);
typedef int	(*getnonblock_op_t)(pcap_t *, char *);
typedef int	(*setnonblock_op_t)(pcap_t *, int, char *);
typedef int	(*stats_op_t)(pcap_t *, struct pcap_stat *);
#ifdef WIN32
typedef int	(*setbuff_op_t)(pcap_t *, int);
typedef int	(*setmode_op_t)(pcap_t *, int);
typedef int	(*setmintocopy_op_t)(pcap_t *, int);
#endif
typedef void	(*cleanup_op_t)(pcap_t *);

struct pcap {
#ifdef WIN32
	ADAPTER *adapter;
	LPPACKET Packet;
	int nonblock;
#else
	int fd;
	int selectable_fd;
	int send_fd;
#endif /* WIN32 */

#ifdef HAVE_LIBDLPI
	dlpi_handle_t dlpi_hd;
#endif
	int snapshot;
	int linktype;		/* Network linktype */
	int linktype_ext;       /* Extended information stored in the linktype field of a file */
	int tzoff;		/* timezone offset */
	int offset;		/* offset for proper alignment */
	int activated;		/* true if the capture is really started */
	int oldstyle;		/* if we're opening with pcap_open_live() */

	int break_loop;		/* flag set to force break from packet-reading loop */

#ifdef PCAP_FDDIPAD
	int fddipad;
#endif

#ifdef MSDOS
        void (*wait_proc)(void); /*          call proc while waiting */
#endif

	struct pcap_sf sf;
	struct pcap_md md;
	struct pcap_opt opt;

	/*
	 * Read buffer.
	 */
	int bufsize;
	u_char *buffer;
	u_char *bp;
	int cc;

	/*
	 * Place holder for pcap_next().
	 */
	u_char *pkt;

	/* We're accepting only packets in this direction/these directions. */
	pcap_direction_t direction;

	/*
	 * Methods.
	 */
	activate_op_t activate_op;
	can_set_rfmon_op_t can_set_rfmon_op;
	read_op_t read_op;
	inject_op_t inject_op;
	setfilter_op_t setfilter_op;
	setdirection_op_t setdirection_op;
	set_datalink_op_t set_datalink_op;
	getnonblock_op_t getnonblock_op;
	setnonblock_op_t setnonblock_op;
	stats_op_t stats_op;

	/*
	 * Routine to use as callback for pcap_next()/pcap_next_ex().
	 */
	pcap_handler oneshot_callback;

#ifdef WIN32
	/*
	 * These are, at least currently, specific to the Win32 NPF
	 * driver.
	 */
	setbuff_op_t setbuff_op;
	setmode_op_t setmode_op;
	setmintocopy_op_t setmintocopy_op;
#endif
	cleanup_op_t cleanup_op;

	/*
	 * Placeholder for filter code if bpf not in kernel.
	 */
	struct bpf_program fcode;

	char errbuf[PCAP_ERRBUF_SIZE + 1];
	int dlt_count;
	u_int *dlt_list;

	struct pcap_pkthdr pcap_header;	/* This is needed for the pcap_next_ex() to work */
};

/*
 * This is a timeval as stored in a savefile.
 * It has to use the same types everywhere, independent of the actual
 * `struct timeval'; `struct timeval' has 32-bit tv_sec values on some
 * platforms and 64-bit tv_sec values on other platforms, and writing
 * out native `struct timeval' values would mean files could only be
 * read on systems with the same tv_sec size as the system on which
 * the file was written.
 */

struct pcap_timeval {
    bpf_int32 tv_sec;		/* seconds */
    bpf_int32 tv_usec;		/* microseconds */
};

/*
 * This is a `pcap_pkthdr' as actually stored in a savefile.
 *
 * Do not change the format of this structure, in any way (this includes
 * changes that only affect the length of fields in this structure),
 * and do not make the time stamp anything other than seconds and
 * microseconds (e.g., seconds and nanoseconds).  Instead:
 *
 *	introduce a new structure for the new format;
 *
 *	send mail to "tcpdump-workers@lists.tcpdump.org", requesting
 *	a new magic number for your new capture file format, and, when
 *	you get the new magic number, put it in "savefile.c";
 *
 *	use that magic number for save files with the changed record
 *	header;
 *
 *	make the code in "savefile.c" capable of reading files with
 *	the old record header as well as files with the new record header
 *	(using the magic number to determine the header format).
 *
 * Then supply the changes as a patch at
 *
 *	http://sourceforge.net/projects/libpcap/
 *
 * so that future versions of libpcap and programs that use it (such as
 * tcpdump) will be able to read your new capture file format.
 */

struct pcap_sf_pkthdr {
    struct pcap_timeval ts;	/* time stamp */
    bpf_u_int32 caplen;		/* length of portion present */
    bpf_u_int32 len;		/* length this packet (off wire) */
};

/*
 * How a `pcap_pkthdr' is actually stored in savefiles written
 * by some patched versions of libpcap (e.g. the ones in Red
 * Hat Linux 6.1 and 6.2).
 *
 * Do not change the format of this structure, in any way (this includes
 * changes that only affect the length of fields in this structure).
 * Instead, introduce a new structure, as per the above.
 */

struct pcap_sf_patched_pkthdr {
    struct pcap_timeval ts;	/* time stamp */
    bpf_u_int32 caplen;		/* length of portion present */
    bpf_u_int32 len;		/* length this packet (off wire) */
    int		index;
    unsigned short protocol;
    unsigned char pkt_type;
};

/*
 * User data structure for the one-shot callback used for pcap_next()
 * and pcap_next_ex().
 */
struct oneshot_userdata {
	struct pcap_pkthdr *hdr;
	const u_char **pkt;
	pcap_t *pd;
};

int	yylex(void);

#ifndef min
#define min(a, b) ((a) > (b) ? (b) : (a))
#endif

/* XXX should these be in pcap.h? */
int	pcap_offline_read(pcap_t *, int, pcap_handler, u_char *);
int	pcap_read(pcap_t *, int cnt, pcap_handler, u_char *);

#ifndef HAVE_STRLCPY
#define strlcpy(x, y, z) \
	(strncpy((x), (y), (z)), \
	 ((z) <= 0 ? 0 : ((x)[(z) - 1] = '\0')), \
	 strlen((y)))
#endif

#include <stdarg.h>

#if !defined(HAVE_SNPRINTF)
#define snprintf pcap_snprintf
extern int snprintf (char *, size_t, const char *, ...);
#endif

#if !defined(HAVE_VSNPRINTF)
#define vsnprintf pcap_vsnprintf
extern int vsnprintf (char *, size_t, const char *, va_list ap);
#endif

/*
 * Routines that most pcap implementations can use for non-blocking mode.
 */
#if !defined(WIN32) && !defined(MSDOS)
int	pcap_getnonblock_fd(pcap_t *, char *);
int	pcap_setnonblock_fd(pcap_t *p, int, char *);
#endif

pcap_t	*pcap_create_common(const char *, char *);
int	pcap_do_addexit(pcap_t *);
void	pcap_add_to_pcaps_to_close(pcap_t *);
void	pcap_remove_from_pcaps_to_close(pcap_t *);
void	pcap_cleanup_live_common(pcap_t *);
int	pcap_not_initialized(pcap_t *);
int	pcap_check_activated(pcap_t *);

/*
 * Internal interfaces for "pcap_findalldevs()".
 *
 * "pcap_platform_finddevs()" is a platform-dependent routine to
 * add devices not found by the "standard" mechanisms (SIOCGIFCONF,
 * "getifaddrs()", etc..
 *
 * "pcap_add_if()" adds an interface to the list of interfaces.
 */
int	pcap_platform_finddevs(pcap_if_t **, char *);
int	add_addr_to_iflist(pcap_if_t **, const char *, u_int, struct sockaddr *,
	    size_t, struct sockaddr *, size_t, struct sockaddr *, size_t,
	    struct sockaddr *, size_t, char *);
int	pcap_add_if(pcap_if_t **, const char *, u_int, const char *, char *);
struct sockaddr *dup_sockaddr(struct sockaddr *, size_t);
int	add_or_find_if(pcap_if_t **, pcap_if_t **, const char *, u_int,
	    const char *, char *);

#ifdef WIN32
char	*pcap_win32strerror(void);
#endif

int	install_bpf_program(pcap_t *, struct bpf_program *);

int	pcap_strcasecmp(const char *, const char *);

#ifdef __cplusplus
}
#endif

#endif
