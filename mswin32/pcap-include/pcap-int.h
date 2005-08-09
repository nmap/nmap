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
 * @(#) $Header: /tcpdump/master/libpcap/pcap-int.h,v 1.68.2.6 2005/07/07 06:56:04 guy Exp $ (LBL)
 */

#ifndef pcap_int_h
#define pcap_int_h

#ifdef __cplusplus
extern "C" {
#endif

#include <pcap.h>

#ifdef WIN32
#include <packet32.h>
#endif /* WIN32 */

#ifdef MSDOS
#include <fcntl.h>
#include <io.h>
#endif

/*
 * Savefile
 */
typedef enum {
	NOT_SWAPPED,
	SWAPPED,
	MAYBE_SWAPPED
} swapped_type_t;

struct pcap_sf {
	FILE *rfile;
	int swapped;
	int hdrsize;
	swapped_type_t lengths_swapped;
	int version_major;
	int version_minor;
	u_char *base;
};

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
#ifdef linux
	int	sock_packet;	/* using Linux 2.0 compatible interface */
	int	timeout;	/* timeout specified to pcap_open_live */
	int	clear_promisc;	/* must clear promiscuous mode when we close */
	int	cooked;		/* using SOCK_DGRAM rather than SOCK_RAW */
	int	ifindex;	/* interface index of device we're bound to */
	int	lo_ifindex;	/* interface index of the loopback device */
	struct pcap *next;	/* list of open promiscuous sock_packet pcaps */
#endif

#ifdef HAVE_DAG_API
#ifdef HAVE_DAG_STREAMS_API
	u_char	*dag_mem_bottom;	/* DAG card current memory bottom pointer */
	u_char	*dag_mem_top;	/* DAG card current memory top pointer */
#else
	void	*dag_mem_base;	/* DAG card memory base address */
	u_int	dag_mem_bottom;	/* DAG card current memory bottom offset */
	u_int	dag_mem_top;	/* DAG card current memory top offset */
#endif /* HAVE_DAG_STREAMS_API */
	int	dag_fcs_bits;	/* Number of checksum bits from link layer */
	int dag_offset_flags; /* Flags to pass to dag_offset(). */
	int	dag_stream;	/* DAG stream number */
	int	dag_timeout;	/* timeout specified to pcap_open_live.
				 * Same as in linux above, introduce
				 * generally? */
#endif /* HAVE_DAG_API */

#ifdef HAVE_REMOTE
/*!
	There is really a mess with previous variables, and it seems to me that they are not used
	(they are used in pcap_pf.c only). I think we have to start using them.
	The meaning is the following:

	- TotPkts: the amount of packets received by the bpf filter, *before* applying the filter
	- TotAccepted: the amount of packets that satisfies the filter
	- TotDrops: the amount of packet that were dropped into the kernel buffer because of lack of space
	- TotMissed: the amount of packets that were dropped by the physical interface; it is basically 
	the value of the hardware counter into the card. This number is never put to zero, so this number
	takes into account the *total* number of interface drops starting from the interface power-on.
	- OrigMissed: the amount of packets that were dropped by the interface *when the capture begins*.
	This value is used to detect the number of packets dropped by the interface *during the present
	capture*, so that (ps_ifdrops= TotMissed - OrigMissed).
*/
	unsigned int TotNetDrops;	//!< keeps the number of packets that have been dropped by the network
/*!
	\brief It keeps the number of packets that have been received by the application.
	
	Packets dropped by the kernel buffer are not counted in this variable. The variable is always 
	equal to (TotAccepted - TotDrops), exept for the case of remote capture, in which we have also
	packets in fligh, i.e. that have been transmitted by the remote host, but that have not been 
	received (yet) from the client. In this case, (TotAccepted - TotDrops - TotNetDrops) gives a
	wrong result, since this number does not corresponds always to the number of packet received by 
	the application. For this reason, in the remote capture we need another variable that takes
	into account of the number of packets actually received by the application.
*/
	unsigned int TotCapt;
#endif /* HAVE_REMOTE */
};

/*
 * Ultrix, DEC OSF/1^H^H^H^H^H^H^H^H^HDigital UNIX^H^H^H^H^H^H^H^H^H^H^H^H
 * Tru64 UNIX, and NetBSD pad to make everything line up on a nice boundary.
 */
#if defined(ultrix) || defined(__osf__) || (defined(__NetBSD__) && __NetBSD_Version__ > 106000000)
#define       PCAP_FDDIPAD 3
#endif

struct pcap {
#ifdef WIN32
	ADAPTER *adapter;
	LPPACKET Packet;
	int timeout;
	int nonblock;
#else
	int fd;
	int selectable_fd;
	int send_fd;
#endif /* WIN32 */
	int snapshot;
	int linktype;
	int tzoff;		/* timezone offset */
	int offset;		/* offset for proper alignment */

	int break_loop;		/* flag set to force break from packet-reading loop */

#ifdef PCAP_FDDIPAD
	int fddipad;
#endif

#ifdef MSDOS
        int inter_packet_wait;   /* offline: wait between packets */
        void (*wait_proc)(void); /*          call proc while waiting */
#endif

	struct pcap_sf sf;
	struct pcap_md md;

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
	int	(*read_op)(pcap_t *, int cnt, pcap_handler, u_char *);
	int	(*inject_op)(pcap_t *, const void *, size_t);
	int	(*setfilter_op)(pcap_t *, struct bpf_program *);
	int	(*setdirection_op)(pcap_t *, pcap_direction_t);
	int	(*set_datalink_op)(pcap_t *, int);
	int	(*getnonblock_op)(pcap_t *, char *);
	int	(*setnonblock_op)(pcap_t *, int, char *);
	int	(*stats_op)(pcap_t *, struct pcap_stat *);
	void	(*close_op)(pcap_t *);

	/*
	 * Placeholder for filter code if bpf not in kernel.
	 */
	struct bpf_program fcode;

	char errbuf[PCAP_ERRBUF_SIZE + 1];
	int dlt_count;
	u_int *dlt_list;

	struct pcap_pkthdr pcap_header;	/* This is needed for the pcap_next_ex() to work */

#ifdef HAVE_REMOTE
#ifndef WIN32	// Win32 already defines 'timeout'
	int timeout;				//!< timeout to be used in the pcap_open()
#endif
	/*! \brief '1' if we're the network client; needed by several functions (like pcap_setfilter() ) to know if 
		they have to use the socket or they have to open the local adapter. */
	int rmt_clientside;

	SOCKET rmt_sockctrl;		//!< socket ID of the socket used for the control connection
	SOCKET rmt_sockdata;		//!< socket ID of the socket used for the data connection
	int rmt_flags;				//!< we have to save flags, since they are passed by the pcap_open_live(), but they are used by the pcap_startcapture()
	int rmt_capstarted;			//!< 'true' if the capture is already started (needed to knoe if we have to call the pcap_startcapture()
	struct pcap_samp rmt_samp;	//!< Keeps the parameters related to the sampling process.
	char *currentfilter;		//!< Pointer to a buffer (allocated at run-time) that stores the current filter. Needed when flag PCAP_OPENFLAG_NOCAPTURE_RPCAP is turned on.
#endif /* HAVE_REMOTE */
};

/*
 * This is a timeval as stored in disk in a dumpfile.
 * It has to use the same types everywhere, independent of the actual
 * `struct timeval'
 */

struct pcap_timeval {
    bpf_int32 tv_sec;		/* seconds */
    bpf_int32 tv_usec;		/* microseconds */
};

/*
 * How a `pcap_pkthdr' is actually stored in the dumpfile.
 *
 * Do not change the format of this structure, in any way (this includes
 * changes that only affect the length of fields in this structure),
 * and do not make the time stamp anything other than seconds and
 * microseconds (e.g., seconds and nanoseconds).  Instead:
 *
 *	introduce a new structure for the new format;
 *
 *	send mail to "tcpdump-workers@tcpdump.org", requesting a new
 *	magic number for your new capture file format, and, when
 *	you get the new magic number, put it in "savefile.c";
 *
 *	use that magic number for save files with the changed record
 *	header;
 *
 *	make the code in "savefile.c" capable of reading files with
 *	the old record header as well as files with the new record header
 *	(using the magic number to determine the header format).
 *
 * Then supply the changes to "patches@tcpdump.org", so that future
 * versions of libpcap and programs that use it (such as tcpdump) will
 * be able to read your new capture file format.
 */

struct pcap_sf_pkthdr {
    struct pcap_timeval ts;	/* time stamp */
    bpf_u_int32 caplen;		/* length of portion present */
    bpf_u_int32 len;		/* length this packet (off wire) */
};

/*
 * How a `pcap_pkthdr' is actually stored in dumpfiles written
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

void	pcap_close_common(pcap_t *);

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
