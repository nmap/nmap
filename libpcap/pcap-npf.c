/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2010 CACE Technologies, Davis (California)
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
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies
 * nor the names of its contributors may be used to endorse or promote
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
 */

#include <config.h>

#include <errno.h>
#include <limits.h> /* for INT_MAX */
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <Packet32.h>
#include <pcap-int.h>
#include <pcap/dlt.h>

/*
 * XXX - Packet32.h defines bpf_program, so we can't include
 * <pcap/bpf.h>, which also defines it; that's why we define
 * PCAP_DONT_INCLUDE_PCAP_BPF_H,
 *
 * However, no header in the WinPcap or Npcap SDKs defines the
 * macros for BPF code, so we have to define them ourselves.
 */
#define		BPF_RET		0x06
#define		BPF_K		0x00

/* Old-school MinGW have these headers in a different place.
 */
#if defined(__MINGW32__) && !defined(__MINGW64_VERSION_MAJOR)
  #include <ddk/ntddndis.h>
  #include <ddk/ndis.h>
#else
  #include <ntddndis.h>  /* MSVC/TDM-MinGW/MinGW64 */
#endif

#ifdef HAVE_DAG_API
  #include <dagnew.h>
  #include <dagapi.h>
#endif /* HAVE_DAG_API */

#include "diag-control.h"

#include "pcap-airpcap.h"

static int pcap_setfilter_npf(pcap_t *, struct bpf_program *);
static int pcap_setfilter_win32_dag(pcap_t *, struct bpf_program *);
static int pcap_getnonblock_npf(pcap_t *);
static int pcap_setnonblock_npf(pcap_t *, int);

/*dimension of the buffer in the pcap_t structure*/
#define	WIN32_DEFAULT_USER_BUFFER_SIZE 256000

/*dimension of the buffer in the kernel driver NPF */
#define	WIN32_DEFAULT_KERNEL_BUFFER_SIZE 1000000

/* Equivalent to ntohs(), but a lot faster under Windows */
#define SWAPS(_X) ((_X & 0xff) << 8) | (_X >> 8)

/*
 * Private data for capturing on WinPcap/Npcap devices.
 */
struct pcap_win {
	ADAPTER *adapter;		/* the packet32 ADAPTER for the device */
	int nonblock;
	int rfmon_selfstart;		/* a flag tells whether the monitor mode is set by itself */
	int filtering_in_kernel;	/* using kernel filter */

#ifdef HAVE_DAG_API
	int	dag_fcs_bits;		/* Number of checksum bits from link layer */
#endif

#ifdef ENABLE_REMOTE
	int samp_npkt;			/* parameter needed for sampling, with '1 out of N' method has been requested */
	struct timeval samp_time;	/* parameter needed for sampling, with '1 every N ms' method has been requested */
#endif
};

/*
 * Define stub versions of the monitor-mode support routines if this
 * isn't Npcap. HAVE_NPCAP_PACKET_API is defined by Npcap but not
 * WinPcap.
 */
#ifndef HAVE_NPCAP_PACKET_API
static int
PacketIsMonitorModeSupported(PCHAR AdapterName _U_)
{
	/*
	 * We don't support monitor mode.
	 */
	return (0);
}

static int
PacketSetMonitorMode(PCHAR AdapterName _U_, int mode _U_)
{
	/*
	 * This should never be called, as PacketIsMonitorModeSupported()
	 * will return 0, meaning "we don't support monitor mode, so
	 * don't try to turn it on or off".
	 */
	return (0);
}

static int
PacketGetMonitorMode(PCHAR AdapterName _U_)
{
	/*
	 * This should fail, so that pcap_activate_npf() returns
	 * PCAP_ERROR_RFMON_NOTSUP if our caller requested monitor
	 * mode.
	 */
	return (-1);
}
#endif

/*
 * If a driver returns an NTSTATUS value:
 *
 *    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/87fba13e-bf06-450e-83b1-9241dc81e781
 *
 * with the "Customer" bit set, it will not be mapped to a Windows error
 * value in userland, so it will be returned by GetLastError().
 *
 * Note that "driver" here includes the Npcap NPF driver, as various
 * versions would take NT status values and set the "Customer" bit
 * before returning the status code.  The commit message for the
 * change that started doing that is
 *
 *    Returned a customer-defined NTSTATUS in OID requests to avoid
 *    NTSTATUS-to-Win32 Error code translation.
 *
 * but I don't know why the goal was to avoid that translation.  For
 * a while, I suspected that the NT status STATUS_NOT_SUPPORTED was
 * getting mapped to ERROR_GEN_FAILURE, but, in the cases where
 * attempts to set promiscuous mode on regular Ethernet devices were
 * failing with ERROR_GEN_FAILURE, it turns out that the drivers for
 * those devices were NetAdapterCx drivers, and Microsoft's NetAdapterCx
 * mechanism wasn't providing the correct "bytes processed" value on
 * attempts to set OIDs, and the Npcap NPF driver was checking for
 * that and returning STATUS_UNSUCCESSFUL, which gets mapped to
 * ERROR_GEN_FAILURE, so perhaps there's no need to avoid that
 * translation.
 *
 * Attempting to set the hardware filter on a Microsoft Surface Pro's
 * Mobile Broadband Adapter returns an error that appears to be
 * NDIS_STATUS_NOT_SUPPORTED ORed with the "Customer" bit, so it's
 * probably indicating that it doesn't support that.  It was probably
 * the NPF driver setting that bit.
 */
#define NT_STATUS_CUSTOMER_DEFINED	0x20000000

/*
 * PacketRequest() makes a DeviceIoControl() call to the NPF driver to
 * perform the OID request, with a BIOCQUERYOID ioctl.  The kernel code
 * should get back one of NDIS_STATUS_INVALID_OID, NDIS_STATUS_NOT_SUPPORTED,
 * or NDIS_STATUS_NOT_RECOGNIZED if the OID request isn't supported by
 * the OS or the driver.
 *
 * Currently, that code may be returned by the Npcap NPF driver with the
 * NT_STATUS_CUSTOMER_DEFINED bit.  That prevents the return status from
 * being mapped to a Windows error code; if the NPF driver were to stop
 * ORing in the NT_STATUS_CUSTOMER_DEFINED bit, it's not obvious how those
 * the NDIS_STATUS_ values that don't correspond to NTSTATUS values would
 * be translated to Windows error values (NDIS_STATUS_NOT_SUPPORTED is
 * the same as STATUS_NOT_SUPPORTED, which is an NTSTATUS value that is
 * mapped to ERROR_NOT_SUPPORTED).
 */
#define NDIS_STATUS_INVALID_OID		0xc0010017
#define NDIS_STATUS_NOT_SUPPORTED	0xc00000bb	/* STATUS_NOT_SUPPORTED */
#define NDIS_STATUS_NOT_RECOGNIZED	0x00010001

static int
oid_get_request(ADAPTER *adapter, bpf_u_int32 oid, void *data, size_t *lenp,
    char *errbuf)
{
	PACKET_OID_DATA *oid_data_arg;

	/*
	 * Allocate a PACKET_OID_DATA structure to hand to PacketRequest().
	 * It should be big enough to hold "*lenp" bytes of data; it
	 * will actually be slightly larger, as PACKET_OID_DATA has a
	 * 1-byte data array at the end, standing in for the variable-length
	 * data that's actually there.
	 */
	oid_data_arg = malloc(sizeof (PACKET_OID_DATA) + *lenp);
	if (oid_data_arg == NULL) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "Couldn't allocate argument buffer for PacketRequest");
		return (PCAP_ERROR);
	}

	/*
	 * No need to copy the data - we're doing a fetch.
	 */
	oid_data_arg->Oid = oid;
	oid_data_arg->Length = (ULONG)(*lenp);	/* XXX - check for ridiculously large value? */
	if (!PacketRequest(adapter, FALSE, oid_data_arg)) {
		pcapint_fmt_errmsg_for_win32_err(errbuf, PCAP_ERRBUF_SIZE,
		    GetLastError(), "Error calling PacketRequest");
		free(oid_data_arg);
		return (-1);
	}

	/*
	 * Get the length actually supplied.
	 */
	*lenp = oid_data_arg->Length;

	/*
	 * Copy back the data we fetched.
	 */
	memcpy(data, oid_data_arg->Data, *lenp);
	free(oid_data_arg);
	return (0);
}

static int
pcap_stats_npf(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_win *pw = p->priv;
	struct bpf_stat bstats;

	/*
	 * Try to get statistics.
	 *
	 * (Please note - "struct pcap_stat" is *not* the same as
	 * WinPcap's "struct bpf_stat". It might currently have the
	 * same layout, but let's not cheat.
	 *
	 * Note also that we don't fill in ps_capt, as we might have
	 * been called by code compiled against an earlier version of
	 * WinPcap that didn't have ps_capt, in which case filling it
	 * in would stomp on whatever comes after the structure passed
	 * to us.
	 */
	if (!PacketGetStats(pw->adapter, &bstats)) {
		pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
		    GetLastError(), "PacketGetStats error");
		return (-1);
	}
	ps->ps_recv = bstats.bs_recv;
	ps->ps_drop = bstats.bs_drop;

	/*
	 * XXX - PacketGetStats() doesn't fill this in, so we just
	 * return 0.
	 */
#if 0
	ps->ps_ifdrop = bstats.ps_ifdrop;
#else
	ps->ps_ifdrop = 0;
#endif

	return (0);
}

/*
 * Win32-only routine for getting statistics.
 *
 * This way is definitely safer than passing the pcap_stat * from the userland.
 * In fact, there could happen than the user allocates a variable which is not
 * big enough for the new structure, and the library will write in a zone
 * which is not allocated to this variable.
 *
 * In this way, we're pretty sure we are writing on memory allocated to this
 * variable.
 *
 * XXX - but this is the wrong way to handle statistics.  Instead, we should
 * have an API that returns data in a form like the Options section of a
 * pcapng Interface Statistics Block:
 *
 *    https://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#rfc.section.4.6
 *
 * which would let us add new statistics straightforwardly and indicate which
 * statistics we are and are *not* providing, rather than having to provide
 * possibly-bogus values for statistics we can't provide.
 */
static struct pcap_stat *
pcap_stats_ex_npf(pcap_t *p, int *pcap_stat_size)
{
	struct pcap_win *pw = p->priv;
	struct bpf_stat bstats;

	*pcap_stat_size = sizeof (p->stat);

	/*
	 * Try to get statistics.
	 *
	 * (Please note - "struct pcap_stat" is *not* the same as
	 * WinPcap's "struct bpf_stat". It might currently have the
	 * same layout, but let's not cheat.)
	 */
	if (!PacketGetStatsEx(pw->adapter, &bstats)) {
		pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
		    GetLastError(), "PacketGetStatsEx error");
		return (NULL);
	}
	p->stat.ps_recv = bstats.bs_recv;
	p->stat.ps_drop = bstats.bs_drop;
	p->stat.ps_ifdrop = bstats.ps_ifdrop;
	/*
	 * Just in case this is ever compiled for a target other than
	 * Windows, which is somewhere between extremely unlikely and
	 * impossible.
	 */
#ifdef _WIN32
	p->stat.ps_capt = bstats.bs_capt;
#endif
	return (&p->stat);
}

/* Set the dimension of the kernel-level capture buffer */
static int
pcap_setbuff_npf(pcap_t *p, int dim)
{
	struct pcap_win *pw = p->priv;

	if(PacketSetBuff(pw->adapter,dim)==FALSE)
	{
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "driver error: not enough memory to allocate the kernel buffer");
		return (-1);
	}
	return (0);
}

/* Set the driver working mode */
static int
pcap_setmode_npf(pcap_t *p, int mode)
{
	struct pcap_win *pw = p->priv;

	if(PacketSetMode(pw->adapter,mode)==FALSE)
	{
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "driver error: working mode not recognized");
		return (-1);
	}

	return (0);
}

/*set the minimum amount of data that will release a read call*/
static int
pcap_setmintocopy_npf(pcap_t *p, int size)
{
	struct pcap_win *pw = p->priv;

	if(PacketSetMinToCopy(pw->adapter, size)==FALSE)
	{
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "driver error: unable to set the requested mintocopy size");
		return (-1);
	}
	return (0);
}

static HANDLE
pcap_getevent_npf(pcap_t *p)
{
	struct pcap_win *pw = p->priv;

	return (PacketGetReadEvent(pw->adapter));
}

static int
pcap_oid_get_request_npf(pcap_t *p, bpf_u_int32 oid, void *data, size_t *lenp)
{
	struct pcap_win *pw = p->priv;

	return (oid_get_request(pw->adapter, oid, data, lenp, p->errbuf));
}

static int
pcap_oid_set_request_npf(pcap_t *p, bpf_u_int32 oid, const void *data,
    size_t *lenp)
{
	struct pcap_win *pw = p->priv;
	PACKET_OID_DATA *oid_data_arg;

	/*
	 * Allocate a PACKET_OID_DATA structure to hand to PacketRequest().
	 * It should be big enough to hold "*lenp" bytes of data; it
	 * will actually be slightly larger, as PACKET_OID_DATA has a
	 * 1-byte data array at the end, standing in for the variable-length
	 * data that's actually there.
	 */
	oid_data_arg = malloc(sizeof (PACKET_OID_DATA) + *lenp);
	if (oid_data_arg == NULL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "Couldn't allocate argument buffer for PacketRequest");
		return (PCAP_ERROR);
	}

	oid_data_arg->Oid = oid;
	oid_data_arg->Length = (ULONG)(*lenp);	/* XXX - check for ridiculously large value? */
	memcpy(oid_data_arg->Data, data, *lenp);
	if (!PacketRequest(pw->adapter, TRUE, oid_data_arg)) {
		pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
		    GetLastError(), "Error calling PacketRequest");
		free(oid_data_arg);
		return (PCAP_ERROR);
	}

	/*
	 * Get the length actually copied.
	 */
	*lenp = oid_data_arg->Length;

	/*
	 * No need to copy the data - we're doing a set.
	 */
	free(oid_data_arg);
	return (0);
}

static u_int
pcap_sendqueue_transmit_npf(pcap_t *p, pcap_send_queue *queue, int sync)
{
	struct pcap_win *pw = p->priv;
	u_int res;

	res = PacketSendPackets(pw->adapter,
		queue->buffer,
		queue->len,
		(BOOLEAN)sync);

	if(res != queue->len){
		pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
		    GetLastError(), "Error queueing packets");
	}

	return (res);
}

static int
pcap_setuserbuffer_npf(pcap_t *p, int size)
{
	unsigned char *new_buff;

	if (size<=0) {
		/* Bogus parameter */
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "Error: invalid size %d",size);
		return (-1);
	}

	/* Allocate the buffer */
	new_buff=(unsigned char*)malloc(sizeof(char)*size);

	if (!new_buff) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "Error: not enough memory");
		return (-1);
	}

	free(p->buffer);

	p->buffer=new_buff;
	p->bufsize=size;

	return (0);
}

#ifdef HAVE_NPCAP_PACKET_API
/*
 * Kernel dump mode isn't supported in Npcap; calls to PacketSetDumpName(),
 * PacketSetDumpLimits(), and PacketIsDumpEnded() will get compile-time
 * deprecation warnings.
 *
 * Avoid calling them; just return errors indicating that kernel dump
 * mode isn't supported in Npcap.
 */
static int
pcap_live_dump_npf(pcap_t *p, char *filename _U_, int maxsize _U_,
    int maxpacks _U_)
{
	snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
	    "Npcap doesn't support kernel dump mode");
	return (-1);
}
static int
pcap_live_dump_ended_npf(pcap_t *p, int sync)
{
	snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
	    "Npcap doesn't support kernel dump mode");
	return (-1);
}
#else /* HAVE_NPCAP_PACKET_API */
static int
pcap_live_dump_npf(pcap_t *p, char *filename, int maxsize, int maxpacks)
{
	struct pcap_win *pw = p->priv;
	BOOLEAN res;

	/* Set the packet driver in dump mode */
	res = PacketSetMode(pw->adapter, PACKET_MODE_DUMP);
	if(res == FALSE){
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "Error setting dump mode");
		return (-1);
	}

	/* Set the name of the dump file */
	res = PacketSetDumpName(pw->adapter, filename, (int)strlen(filename));
	if(res == FALSE){
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "Error setting kernel dump file name");
		return (-1);
	}

	/* Set the limits of the dump file */
	res = PacketSetDumpLimits(pw->adapter, maxsize, maxpacks);
	if(res == FALSE) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				"Error setting dump limit");
		return (-1);
	}

	return (0);
}

static int
pcap_live_dump_ended_npf(pcap_t *p, int sync)
{
	struct pcap_win *pw = p->priv;

	return (PacketIsDumpEnded(pw->adapter, (BOOLEAN)sync));
}
#endif /* HAVE_NPCAP_PACKET_API */

#ifdef HAVE_AIRPCAP_API
static PAirpcapHandle
pcap_get_airpcap_handle_npf(pcap_t *p)
{
	struct pcap_win *pw = p->priv;

	return (PacketGetAirPcapHandle(pw->adapter));
}
#else /* HAVE_AIRPCAP_API */
static PAirpcapHandle
pcap_get_airpcap_handle_npf(pcap_t *p _U_)
{
	return (NULL);
}
#endif /* HAVE_AIRPCAP_API */

static int
pcap_read_npf(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	PACKET Packet;
	int cc;
	int n;
	register u_char *bp, *ep;
	u_char *datap;
	struct pcap_win *pw = p->priv;

	cc = p->cc;
	if (cc == 0) {
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

		/*
		 * Capture the packets.
		 *
		 * The PACKET structure had a bunch of extra stuff for
		 * Windows 9x/Me, but the only interesting data in it
		 * in the versions of Windows that we support is just
		 * a copy of p->buffer, a copy of p->buflen, and the
		 * actual number of bytes read returned from
		 * PacketReceivePacket(), none of which has to be
		 * retained from call to call, so we just keep one on
		 * the stack.
		 */
		PacketInitPacket(&Packet, (BYTE *)p->buffer, p->bufsize);
		if (!PacketReceivePacket(pw->adapter, &Packet, TRUE)) {
			/*
			 * Did the device go away?
			 * If so, the error we get can either be
			 * ERROR_GEN_FAILURE or ERROR_DEVICE_REMOVED.
			 */
			DWORD errcode = GetLastError();

			if (errcode == ERROR_GEN_FAILURE ||
			    errcode == ERROR_DEVICE_REMOVED) {
				/*
				 * The device on which we're capturing
				 * went away, or it became unusable
				 * by NPF due to a suspend/resume.
				 *
				 * ERROR_GEN_FAILURE comes from
				 * STATUS_UNSUCCESSFUL, as well as some
				 * other NT status codes that the Npcap
				 * driver is unlikely to return.
				 * XXX - hopefully no other error
				 * conditions are indicated by this.
				 *
				 * ERROR_DEVICE_REMOVED comes from
				 * STATUS_DEVICE_REMOVED.
				 *
				 * We report the Windows status code
				 * name and the corresponding NT status
				 * code name, for the benefit of attempts
				 * to debug cases where this error is
				 * reported when the device *wasn't*
				 * removed, either because it's not
				 * removable, it's removable but wasn't
				 * removed, or it's a device that doesn't
				 * correspond to a physical device.
				 *
				 * XXX - we really should return an
				 * appropriate error for that, but
				 * pcap_dispatch() etc. aren't
				 * documented as having error returns
				 * other than PCAP_ERROR or PCAP_ERROR_BREAK.
				 */
				const char *errcode_msg;

				if (errcode == ERROR_GEN_FAILURE)
					errcode_msg = "ERROR_GEN_FAILURE/STATUS_UNSUCCESSFUL";
				else
					errcode_msg = "ERROR_DEVICE_REMOVED/STATUS_DEVICE_REMOVED";
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "The interface disappeared (error code %s)",
				    errcode_msg);
			} else {
				pcapint_fmt_errmsg_for_win32_err(p->errbuf,
				    PCAP_ERRBUF_SIZE, errcode,
				    "PacketReceivePacket error");
			}
			return (PCAP_ERROR);
		}

		cc = Packet.ulBytesReceived;

		bp = p->buffer;
	}
	else
		bp = p->bp;

	/*
	 * Loop through each packet.
	 *
	 * This assumes that a single buffer of packets will have
	 * <= INT_MAX packets, so the packet count doesn't overflow.
	 */
#define bhp ((struct bpf_hdr *)bp)
	n = 0;
	ep = bp + cc;
	for (;;) {
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
			if (n == 0) {
				p->break_loop = 0;
				return (PCAP_ERROR_BREAK);
			} else {
				p->bp = bp;
				p->cc = (int) (ep - bp);
				return (n);
			}
		}
		if (bp >= ep)
			break;

		caplen = bhp->bh_caplen;
		hdrlen = bhp->bh_hdrlen;
		datap = bp + hdrlen;

		/*
		 * Short-circuit evaluation: if using BPF filter
		 * in kernel, no need to do it now - we already know
		 * the packet passed the filter.
		 *
		 * XXX - pcapint_filter() should always return TRUE if
		 * handed a null pointer for the program, but it might
		 * just try to "run" the filter, so we check here.
		 */
		if (pw->filtering_in_kernel ||
		    p->fcode.bf_insns == NULL ||
		    pcapint_filter(p->fcode.bf_insns, datap, bhp->bh_datalen, caplen)) {
#ifdef ENABLE_REMOTE
			switch (p->rmt_samp.method) {

			case PCAP_SAMP_1_EVERY_N:
				pw->samp_npkt = (pw->samp_npkt + 1) % p->rmt_samp.value;

				/* Discard all packets that are not '1 out of N' */
				if (pw->samp_npkt != 0) {
					bp += Packet_WORDALIGN(caplen + hdrlen);
					continue;
				}
				break;

			case PCAP_SAMP_FIRST_AFTER_N_MS:
			    {
				struct pcap_pkthdr *pkt_header = (struct pcap_pkthdr*) bp;

				/*
				 * Check if the timestamp of the arrived
				 * packet is smaller than our target time.
				 */
				if (pkt_header->ts.tv_sec < pw->samp_time.tv_sec ||
				   (pkt_header->ts.tv_sec == pw->samp_time.tv_sec && pkt_header->ts.tv_usec < pw->samp_time.tv_usec)) {
					bp += Packet_WORDALIGN(caplen + hdrlen);
					continue;
				}

				/*
				 * The arrived packet is suitable for being
				 * delivered to our caller, so let's update
				 * the target time.
				 */
				pw->samp_time.tv_usec = pkt_header->ts.tv_usec + p->rmt_samp.value * 1000;
				if (pw->samp_time.tv_usec > 1000000) {
					pw->samp_time.tv_sec = pkt_header->ts.tv_sec + pw->samp_time.tv_usec / 1000000;
					pw->samp_time.tv_usec = pw->samp_time.tv_usec % 1000000;
				}
			    }
			}
#endif	/* ENABLE_REMOTE */

			/*
			 * XXX A bpf_hdr matches a pcap_pkthdr.
			 */
			(*callback)(user, (struct pcap_pkthdr*)bp, datap);
			bp += Packet_WORDALIGN(caplen + hdrlen);
			if (++n >= cnt && !PACKET_COUNT_IS_UNLIMITED(cnt)) {
				p->bp = bp;
				p->cc = (int) (ep - bp);
				return (n);
			}
		} else {
			/*
			 * Skip this packet.
			 */
			bp += Packet_WORDALIGN(caplen + hdrlen);
		}
	}
#undef bhp
	p->cc = 0;
	return (n);
}

#ifdef HAVE_DAG_API
static int
pcap_read_win32_dag(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	struct pcap_win *pw = p->priv;
	PACKET Packet;
	u_char *dp = NULL;
	int	packet_len = 0, caplen = 0;
	struct pcap_pkthdr	pcap_header;
	u_char *endofbuf;
	int n = 0;
	dag_record_t *header;
	unsigned erf_record_len;
	ULONGLONG ts;
	int cc;
	unsigned swt;
	unsigned dfp = pw->adapter->DagFastProcess;

	cc = p->cc;
	if (cc == 0) /* Get new packets only if we have processed all the ones of the previous read */
	{
		/*
		 * Get new packets from the network.
		 *
		 * The PACKET structure had a bunch of extra stuff for
		 * Windows 9x/Me, but the only interesting data in it
		 * in the versions of Windows that we support is just
		 * a copy of p->buffer, a copy of p->buflen, and the
		 * actual number of bytes read returned from
		 * PacketReceivePacket(), none of which has to be
		 * retained from call to call, so we just keep one on
		 * the stack.
		 */
		PacketInitPacket(&Packet, (BYTE *)p->buffer, p->bufsize);
		if (!PacketReceivePacket(pw->adapter, &Packet, TRUE)) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "read error: PacketReceivePacket failed");
			return (-1);
		}

		cc = Packet.ulBytesReceived;
		if(cc == 0)
			/* The timeout has expired but we no packets arrived */
			return (0);
		header = (dag_record_t*)pw->adapter->DagBuffer;
	}
	else
		header = (dag_record_t*)p->bp;

	endofbuf = (char*)header + cc;

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
	if (PACKET_COUNT_IS_UNLIMITED(cnt))
		cnt = INT_MAX;

	/*
	 * Cycle through the packets
	 */
	do
	{
		erf_record_len = SWAPS(header->rlen);
		if((char*)header + erf_record_len > endofbuf)
			break;

		/* Increase the number of captured packets */
		p->stat.ps_recv++;

		/* Find the beginning of the packet */
		dp = ((u_char *)header) + dag_record_size;

		/* Determine actual packet len */
		switch(header->type)
		{
		case TYPE_ATM:
			packet_len = ATM_SNAPLEN;
			caplen = ATM_SNAPLEN;
			dp += 4;

			break;

		case TYPE_ETH:
			swt = SWAPS(header->wlen);
			packet_len = swt - (pw->dag_fcs_bits);
			caplen = erf_record_len - dag_record_size - 2;
			if (caplen > packet_len)
			{
				caplen = packet_len;
			}
			dp += 2;

			break;

		case TYPE_HDLC_POS:
			swt = SWAPS(header->wlen);
			packet_len = swt - (pw->dag_fcs_bits);
			caplen = erf_record_len - dag_record_size;
			if (caplen > packet_len)
			{
				caplen = packet_len;
			}

			break;
		}

		if(caplen > p->snapshot)
			caplen = p->snapshot;

		/*
		 * Has "pcap_breakloop()" been called?
		 * If so, return immediately - if we haven't read any
		 * packets, clear the flag and return -2 to indicate
		 * that we were told to break out of the loop, otherwise
		 * leave the flag set, so that the *next* call will break
		 * out of the loop without having read any packets, and
		 * return the number of packets we've processed so far.
		 */
		if (p->break_loop)
		{
			if (n == 0)
			{
				p->break_loop = 0;
				return (-2);
			}
			else
			{
				p->bp = (char*)header;
				p->cc = endofbuf - (char*)header;
				return (n);
			}
		}

		if(!dfp)
		{
			/* convert between timestamp formats */
			ts = header->ts;
			pcap_header.ts.tv_sec = (int)(ts >> 32);
			ts = (ts & 0xffffffffi64) * 1000000;
			ts += 0x80000000; /* rounding */
			pcap_header.ts.tv_usec = (int)(ts >> 32);
			if (pcap_header.ts.tv_usec >= 1000000) {
				pcap_header.ts.tv_usec -= 1000000;
				pcap_header.ts.tv_sec++;
			}
		}

		/* No underlying filtering system. We need to filter on our own */
		if (p->fcode.bf_insns)
		{
			if (pcapint_filter(p->fcode.bf_insns, dp, packet_len, caplen) == 0)
			{
				/* Move to next packet */
				header = (dag_record_t*)((char*)header + erf_record_len);
				continue;
			}
		}

		/* Fill the header for the user supplied callback function */
		pcap_header.caplen = caplen;
		pcap_header.len = packet_len;

		/* Call the callback function */
		(*callback)(user, &pcap_header, dp);

		/* Move to next packet */
		header = (dag_record_t*)((char*)header + erf_record_len);

		/* Stop if the number of packets requested by user has been reached*/
		if (++n >= cnt && !PACKET_COUNT_IS_UNLIMITED(cnt))
		{
			p->bp = (char*)header;
			p->cc = endofbuf - (char*)header;
			return (n);
		}
	}
	while((u_char*)header < endofbuf);

	return (1);
}
#endif /* HAVE_DAG_API */

/* Send a packet to the network */
static int
pcap_inject_npf(pcap_t *p, const void *buf, int size)
{
	struct pcap_win *pw = p->priv;
	PACKET pkt;

	PacketInitPacket(&pkt, (PVOID)buf, size);
	if(PacketSendPacket(pw->adapter,&pkt,TRUE) == FALSE) {
		pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
		    GetLastError(), "send error: PacketSendPacket failed");
		return (-1);
	}

	/*
	 * We assume it all got sent if "PacketSendPacket()" succeeded.
	 * "pcap_inject()" is expected to return the number of bytes
	 * sent.
	 */
	return (size);
}

static void
pcap_cleanup_npf(pcap_t *p)
{
	struct pcap_win *pw = p->priv;

	if (pw->adapter != NULL) {
		PacketCloseAdapter(pw->adapter);
		pw->adapter = NULL;
	}
	if (pw->rfmon_selfstart)
	{
		PacketSetMonitorMode(p->opt.device, 0);
	}
	pcapint_cleanup_live_common(p);
}

static void
pcap_breakloop_npf(pcap_t *p)
{
	pcapint_breakloop_common(p);
	struct pcap_win *pw = p->priv;

	/* XXX - what if this fails? */
	SetEvent(PacketGetReadEvent(pw->adapter));
}

static int
pcap_activate_npf(pcap_t *p)
{
	struct pcap_win *pw = p->priv;
	NetType type;
	int res;
	int status = 0;
	struct bpf_insn total_insn;
	struct bpf_program total_prog;

	if (p->opt.rfmon) {
		/*
		 * Monitor mode is supported on Windows Vista and later.
		 */
		if (PacketGetMonitorMode(p->opt.device) == 1)
		{
			pw->rfmon_selfstart = 0;
		}
		else
		{
			if ((res = PacketSetMonitorMode(p->opt.device, 1)) != 1)
			{
				pw->rfmon_selfstart = 0;
				// Monitor mode is not supported.
				if (res == 0)
				{
					return PCAP_ERROR_RFMON_NOTSUP;
				}
				else
				{
					return PCAP_ERROR;
				}
			}
			else
			{
				pw->rfmon_selfstart = 1;
			}
		}
	}

	/* Init Winsock if it hasn't already been initialized */
	pcap_wsockinit();

	pw->adapter = PacketOpenAdapter(p->opt.device);

	if (pw->adapter == NULL)
	{
		DWORD errcode = GetLastError();

		/*
		 * What error did we get when trying to open the adapter?
		 */
		switch (errcode) {

		case ERROR_BAD_UNIT:
			/*
			 * There's no such device.
			 * There's nothing to add, so clear the error
			 * message.
			 */
			p->errbuf[0] = '\0';
			return (PCAP_ERROR_NO_SUCH_DEVICE);

		case ERROR_ACCESS_DENIED:
			/*
			 * There is, but we don't have permission to
			 * use it.
			 *
			 * XXX - we currently get ERROR_BAD_UNIT if the
			 * user says "no" to the UAC prompt.
			 */
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "The helper program for \"Admin-only Mode\" must be allowed to make changes to your device");
			return (PCAP_ERROR_PERM_DENIED);

		default:
			/*
			 * Unknown - report details.
			 */
			pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
			    errcode, "Error opening adapter");
			if (pw->rfmon_selfstart)
			{
				PacketSetMonitorMode(p->opt.device, 0);
			}
			return (PCAP_ERROR);
		}
	}

	/*get network type*/
	if(PacketGetNetType (pw->adapter,&type) == FALSE)
	{
		pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
		    GetLastError(), "Cannot determine the network type");
		goto bad;
	}

	/*Set the linktype*/
	switch (type.LinkType)
	{
	/*
	 * NDIS-defined medium types.
	 */
	case NdisMedium802_3:
		p->linktype = DLT_EN10MB;
		/*
		 * This is (presumably) a real Ethernet capture; give it a
		 * link-layer-type list with DLT_EN10MB and DLT_DOCSIS, so
		 * that an application can let you choose it, in case you're
		 * capturing DOCSIS traffic that a Cisco Cable Modem
		 * Termination System is putting out onto an Ethernet (it
		 * doesn't put an Ethernet header onto the wire, it puts raw
		 * DOCSIS frames out on the wire inside the low-level
		 * Ethernet framing).
		 */
		p->dlt_list = (u_int *) malloc(sizeof(u_int) * 2);
		if (p->dlt_list == NULL)
		{
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "malloc");
			goto bad;
		}
		p->dlt_list[0] = DLT_EN10MB;
		p->dlt_list[1] = DLT_DOCSIS;
		p->dlt_count = 2;
		break;

	case NdisMedium802_5:
		/*
		 * Token Ring.
		 */
		p->linktype = DLT_IEEE802;
		break;

	case NdisMediumFddi:
		p->linktype = DLT_FDDI;
		break;

	case NdisMediumWan:
		p->linktype = DLT_EN10MB;
		break;

	case NdisMediumArcnetRaw:
		p->linktype = DLT_ARCNET;
		break;

	case NdisMediumArcnet878_2:
		p->linktype = DLT_ARCNET;
		break;

	case NdisMediumAtm:
		p->linktype = DLT_ATM_RFC1483;
		break;

	case NdisMediumWirelessWan:
		p->linktype = DLT_RAW;
		break;

	case NdisMediumIP:
		p->linktype = DLT_RAW;
		break;

	/*
	 * Npcap-defined medium types.
	 */
	case NdisMediumNull:
		p->linktype = DLT_NULL;
		break;

	case NdisMediumCHDLC:
		p->linktype = DLT_CHDLC;
		break;

	case NdisMediumPPPSerial:
		p->linktype = DLT_PPP_SERIAL;
		break;

	case NdisMediumBare80211:
		p->linktype = DLT_IEEE802_11;
		break;

	case NdisMediumRadio80211:
		p->linktype = DLT_IEEE802_11_RADIO;
		break;

	case NdisMediumPpi:
		p->linktype = DLT_PPI;
		break;

	default:
		/*
		 * An unknown medium type is assumed to supply Ethernet
		 * headers; if not, the user will have to report it,
		 * so that the medium type and link-layer header type
		 * can be determined.  If we were to fail here, we
		 * might get the link-layer type in the error, but
		 * the user wouldn't get a capture, so we wouldn't
		 * be able to determine the link-layer type; we report
		 * a warning with the link-layer type, so at least
		 * some programs will report the warning.
		 */
		p->linktype = DLT_EN10MB;
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "Unknown NdisMedium value %d, defaulting to DLT_EN10MB",
		    type.LinkType);
		status = PCAP_WARNING;
		break;
	}

#ifdef HAVE_PACKET_GET_TIMESTAMP_MODES
	/*
	 * Set the timestamp type.
	 * (Yes, we require PacketGetTimestampModes(), not just
	 * PacketSetTimestampMode().  If we have the former, we
	 * have the latter, unless somebody's using a version
	 * of Npcap that they've hacked to provide the former
	 * but not the latter; if they've done that, either
	 * they're confused or they're trolling us.)
	 */
	switch (p->opt.tstamp_type) {

	case PCAP_TSTAMP_HOST_HIPREC_UNSYNCED:
		/*
		 * Better than low-res, but *not* synchronized with
		 * the OS clock.
		 */
		if (!PacketSetTimestampMode(pw->adapter, TIMESTAMPMODE_SINGLE_SYNCHRONIZATION))
		{
			pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
			    GetLastError(), "Cannot set the time stamp mode to TIMESTAMPMODE_SINGLE_SYNCHRONIZATION");
			goto bad;
		}
		break;

	case PCAP_TSTAMP_HOST_LOWPREC:
		/*
		 * Low-res, but synchronized with the OS clock.
		 */
		if (!PacketSetTimestampMode(pw->adapter, TIMESTAMPMODE_QUERYSYSTEMTIME))
		{
			pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
			    GetLastError(), "Cannot set the time stamp mode to TIMESTAMPMODE_QUERYSYSTEMTIME");
			goto bad;
		}
		break;

	case PCAP_TSTAMP_HOST_HIPREC:
		/*
		 * High-res, and synchronized with the OS clock.
		 */
		if (!PacketSetTimestampMode(pw->adapter, TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE))
		{
			pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
			    GetLastError(), "Cannot set the time stamp mode to TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE");
			goto bad;
		}
		break;

	case PCAP_TSTAMP_HOST:
		/*
		 * XXX - do whatever the default is, for now.
		 * Set to the highest resolution that's synchronized
		 * with the system clock?
		 */
		break;
	}
#endif /* HAVE_PACKET_GET_TIMESTAMP_MODES */

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

	/* Set promiscuous mode */
	if (p->opt.promisc)
	{
		/*
		 * For future reference, in case we ever want to query
		 * whether an adapter supports promiscuous mode, that
		 * would be done on Windows by querying the value
		 * of the OID_GEN_SUPPORTED_PACKET_FILTERS OID.
		 */
		if (PacketSetHwFilter(pw->adapter,NDIS_PACKET_TYPE_PROMISCUOUS) == FALSE)
		{
			DWORD errcode = GetLastError();

			/*
			 * Suppress spurious error generated by non-compliant
			 * MS Surface mobile adapters that appear to
			 * return NDIS_STATUS_NOT_SUPPORTED for attempts
			 * to set the hardware filter.
			 *
			 * It appears to be reporting NDIS_STATUS_NOT_SUPPORTED,
			 * but with the NT status value "Customer" bit set;
			 * the Npcap NPF driver sets that bit in some cases.
			 *
			 * If we knew that this meant "promiscuous mode
			 * isn't supported", we could add a "promiscuous
			 * mode isn't supported" error code and return
			 * that, but:
			 *
			 *    1) we don't know that it means that
			 *    rather than meaning "we reject attempts
			 *    to set the filter, even though the NDIS
			 *    specifications say you shouldn't do that"
			 *
			 * and
			 *
			 *    2) other interface types that don't
			 *    support promiscuous mode, at least
			 *    on UN*Xes, just silently ignore
			 *    attempts to set promiscuous mode
			 *
			 * and rejecting it with an error could disrupt
			 * attempts to capture, as many programs (tcpdump,
			 * *shark) default to promiscuous mode.
			 *
			 * Alternatively, we could return the "promiscuous
			 * mode not supported" *warning* value, so that
			 * correct code will either ignore it or report
			 * it and continue capturing.  (This may require
			 * a pcap_init() flag to request that return
			 * value, so that old incorrect programs that
			 * assume a non-zero return from pcap_activate()
			 * is an error don't break.)
			 *
			 * We check here for ERROR_NOT_SUPPORTED, which
			 * is what NDIS_STATUS_NOT_SUPPORTED (which is
			 * the same value as the NTSTATUS value
			 * STATUS_NOT_SUPPORTED) gets mapped to, as
			 * well as NDIS_STATUS_NOT_SUPPORTED with the
			 * "Customer" bit set.
			 */
			if (errcode != ERROR_NOT_SUPPORTED &&
			    errcode != (NDIS_STATUS_NOT_SUPPORTED|NT_STATUS_CUSTOMER_DEFINED))
			{
				pcapint_fmt_errmsg_for_win32_err(p->errbuf,
				    PCAP_ERRBUF_SIZE, errcode,
				    "failed to set hardware filter to promiscuous mode");
				goto bad;
			}
		}
	}
	else
	{
		/*
		 * NDIS_PACKET_TYPE_ALL_LOCAL selects "All packets sent by
		 * installed protocols and all packets indicated by the NIC",
		 * but if no protocol drivers (like TCP/IP) are installed,
		 * NDIS_PACKET_TYPE_DIRECTED, NDIS_PACKET_TYPE_BROADCAST,
		 * and NDIS_PACKET_TYPE_MULTICAST are needed to capture
		 * incoming frames.
		 */
		if (PacketSetHwFilter(pw->adapter,
			NDIS_PACKET_TYPE_ALL_LOCAL |
			NDIS_PACKET_TYPE_DIRECTED |
			NDIS_PACKET_TYPE_BROADCAST |
			NDIS_PACKET_TYPE_MULTICAST) == FALSE)
		{
			DWORD errcode = GetLastError();

			/*
			 * Suppress spurious error generated by non-compliant
			 * MS Surface mobile adapters.
			 */
			if (errcode != (NDIS_STATUS_NOT_SUPPORTED|NT_STATUS_CUSTOMER_DEFINED))
			{
				pcapint_fmt_errmsg_for_win32_err(p->errbuf,
				    PCAP_ERRBUF_SIZE, errcode,
				    "failed to set hardware filter to non-promiscuous mode");
				goto bad;
			}
		}
	}

	/* Set the buffer size */
	p->bufsize = WIN32_DEFAULT_USER_BUFFER_SIZE;

	if(!(pw->adapter->Flags & INFO_FLAG_DAG_CARD))
	{
	/*
	 * Traditional Adapter
	 */
		/*
		 * If the buffer size wasn't explicitly set, default to
		 * WIN32_DEFAULT_KERNEL_BUFFER_SIZE.
		 */
		if (p->opt.buffer_size == 0)
			p->opt.buffer_size = WIN32_DEFAULT_KERNEL_BUFFER_SIZE;

		if(PacketSetBuff(pw->adapter,p->opt.buffer_size)==FALSE)
		{
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "driver error: not enough memory to allocate the kernel buffer");
			goto bad;
		}

		p->buffer = malloc(p->bufsize);
		if (p->buffer == NULL)
		{
			pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
			    errno, "malloc");
			goto bad;
		}

		if (p->opt.immediate)
		{
			/* tell the driver to copy the buffer as soon as data arrives */
			if(PacketSetMinToCopy(pw->adapter,0)==FALSE)
			{
				pcapint_fmt_errmsg_for_win32_err(p->errbuf,
				    PCAP_ERRBUF_SIZE, GetLastError(),
				    "Error calling PacketSetMinToCopy");
				goto bad;
			}
		}
		else
		{
			/* tell the driver to copy the buffer only if it contains at least 16K */
			if(PacketSetMinToCopy(pw->adapter,16000)==FALSE)
			{
				pcapint_fmt_errmsg_for_win32_err(p->errbuf,
				    PCAP_ERRBUF_SIZE, GetLastError(),
				    "Error calling PacketSetMinToCopy");
				goto bad;
			}
		}
	} else {
		/*
		 * Dag Card
		 */
#ifdef HAVE_DAG_API
		/*
		 * We have DAG support.
		 */
		LONG	status;
		HKEY	dagkey;
		DWORD	lptype;
		DWORD	lpcbdata;
		int		postype = 0;
		char	keyname[512];

		snprintf(keyname, sizeof(keyname), "%s\\CardParams\\%s",
			"SYSTEM\\CurrentControlSet\\Services\\DAG",
			strstr(_strlwr(p->opt.device), "dag"));
		do
		{
			status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname, 0, KEY_READ, &dagkey);
			if(status != ERROR_SUCCESS)
				break;

			status = RegQueryValueEx(dagkey,
				"PosType",
				NULL,
				&lptype,
				(char*)&postype,
				&lpcbdata);

			if(status != ERROR_SUCCESS)
			{
				postype = 0;
			}

			RegCloseKey(dagkey);
		}
		while(FALSE);


		p->snapshot = PacketSetSnapLen(pw->adapter, p->snapshot);

		/* Set the length of the FCS associated to any packet. This value
		 * will be subtracted to the packet length */
		pw->dag_fcs_bits = pw->adapter->DagFcsLen;
#else /* HAVE_DAG_API */
		/*
		 * No DAG support.
		 */
		goto bad;
#endif /* HAVE_DAG_API */
	}

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
	if (!PacketSetBpf(pw->adapter, &total_prog)) {
		pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
		    GetLastError(), "PacketSetBpf");
		status = PCAP_ERROR;
		goto bad;
	}

	PacketSetReadTimeout(pw->adapter, p->opt.timeout);

	/* disable loopback capture if requested */
	if (p->opt.nocapture_local)
	{
		if (!PacketSetLoopbackBehavior(pw->adapter, NPF_DISABLE_LOOPBACK))
		{
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "Unable to disable the capture of loopback packets.");
			goto bad;
		}
	}

#ifdef HAVE_DAG_API
	if(pw->adapter->Flags & INFO_FLAG_DAG_CARD)
	{
		/* install dag specific handlers for read and setfilter */
		p->read_op = pcap_read_win32_dag;
		p->setfilter_op = pcap_setfilter_win32_dag;
	}
	else
	{
#endif /* HAVE_DAG_API */
		/* install traditional npf handlers for read and setfilter */
		p->read_op = pcap_read_npf;
		p->setfilter_op = pcap_setfilter_npf;
#ifdef HAVE_DAG_API
	}
#endif /* HAVE_DAG_API */
	p->setdirection_op = NULL;	/* Not implemented. */
	    /* XXX - can this be implemented on some versions of Windows? */
	p->inject_op = pcap_inject_npf;
	p->set_datalink_op = NULL;	/* can't change data link type */
	p->getnonblock_op = pcap_getnonblock_npf;
	p->setnonblock_op = pcap_setnonblock_npf;
	p->stats_op = pcap_stats_npf;
	p->breakloop_op = pcap_breakloop_npf;
	p->stats_ex_op = pcap_stats_ex_npf;
	p->setbuff_op = pcap_setbuff_npf;
	p->setmode_op = pcap_setmode_npf;
	p->setmintocopy_op = pcap_setmintocopy_npf;
	p->getevent_op = pcap_getevent_npf;
	p->oid_get_request_op = pcap_oid_get_request_npf;
	p->oid_set_request_op = pcap_oid_set_request_npf;
	p->sendqueue_transmit_op = pcap_sendqueue_transmit_npf;
	p->setuserbuffer_op = pcap_setuserbuffer_npf;
	p->live_dump_op = pcap_live_dump_npf;
	p->live_dump_ended_op = pcap_live_dump_ended_npf;
	p->get_airpcap_handle_op = pcap_get_airpcap_handle_npf;
	p->cleanup_op = pcap_cleanup_npf;

	/*
	 * XXX - this is only done because WinPcap supported
	 * pcap_fileno() returning the hFile HANDLE from the
	 * ADAPTER structure.  We make no general guarantees
	 * that the caller can do anything useful with it.
	 *
	 * (Not that we make any general guarantee of that
	 * sort on UN*X, either, anymore, given that not
	 * all capture devices are regular OS network
	 * interfaces.)
	 */
	p->handle = pw->adapter->hFile;

	return (status);
bad:
	pcap_cleanup_npf(p);
	return (PCAP_ERROR);
}

/*
* Check if rfmon mode is supported on the pcap_t for Windows systems.
*/
static int
pcap_can_set_rfmon_npf(pcap_t *p)
{
	return (PacketIsMonitorModeSupported(p->opt.device) == 1);
}

/*
 * Get a list of time stamp types.
 */
#ifdef HAVE_PACKET_GET_TIMESTAMP_MODES
static int
get_ts_types(const char *device, pcap_t *p, char *ebuf)
{
	char *device_copy = NULL;
	ADAPTER *adapter = NULL;
	ULONG num_ts_modes;
	/* Npcap 1.00 driver is buggy and will write 16 bytes regardless of
	 * buffer size. Using a sufficient stack buffer avoids overflow and
	 * avoids a heap allocation in most (currently all) cases.
	 */
	ULONG ts_modes[4];
	BOOL ret;
	DWORD error = ERROR_SUCCESS;
	ULONG *modes = NULL;
	int status = 0;

	do {
		/*
		 * First, find out how many time stamp modes we have.
		 * To do that, we have to open the adapter.
		 *
		 * XXX - PacketOpenAdapter() takes a non-const pointer
		 * as an argument, so we make a copy of the argument and
		 * pass that to it.
		 */
		device_copy = strdup(device);
		if (device_copy == NULL) {
			pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE, errno, "malloc");
			status = -1;
			break;
		}

		adapter = PacketOpenAdapter(device_copy);
		if (adapter == NULL)
		{
			error = GetLastError();
			/*
			 * If we can't open the device now, we won't be
			 * able to later, either.
			 *
			 * If the error is something that indicates
			 * that the device doesn't exist, or that they
			 * don't have permission to open the device - or
			 * perhaps that they don't have permission to get
			 * a list of devices, if PacketOpenAdapter() does
			 * that - the user will find that out when they try
			 * to activate the device; just return an empty
			 * list of time stamp types.
			 *
			 * Treating either of those as errors will, for
			 * example, cause "tcpdump -i <number>" to fail,
			 * because it first tries to pass the interface
			 * name to pcap_create() and pcap_activate(),
			 * in order to handle OSes where interfaces can
			 * have names that are just numbers (stand up
			 * and say hello, Linux!), and, if pcap_activate()
			 * fails with a "no such device" error, checks
			 * whether the interface name is a valid number
			 * and, if so, tries to use it as an index in
			 * the list of interfaces.
			 *
			 * That means pcap_create() must succeed even
			 * for interfaces that don't exist, with the
			 * failure occurring at pcap_activate() time.
			 */
			if (error == ERROR_BAD_UNIT ||
			    error == ERROR_ACCESS_DENIED) {
				p->tstamp_type_count = 0;
				p->tstamp_type_list = NULL;
				status = 0;
			} else {
				pcapint_fmt_errmsg_for_win32_err(ebuf,
				    PCAP_ERRBUF_SIZE, error,
				    "Error opening adapter");
				status = -1;
			}
			break;
		}

		/*
		 * Get the total number of time stamp modes.
		 *
		 * The buffer for PacketGetTimestampModes() is
		 * a sequence of 1 or more ULONGs.  What's
		 * passed to PacketGetTimestampModes() should have
		 * the total number of ULONGs in the first ULONG;
		 * what's returned *from* PacketGetTimestampModes()
		 * has the total number of time stamp modes in
		 * the first ULONG.
		 *
		 * Yes, that means if there are N time stamp
		 * modes, the first ULONG should be set to N+1
		 * on input, and will be set to N on output.
		 *
		 * We first make a call to PacketGetTimestampModes()
		 * with a pointer to a single ULONG set to 1; the
		 * call should fail with ERROR_MORE_DATA (unless
		 * there are *no* modes, but that should never
		 * happen), and that ULONG should be set to the
		 * number of modes.
		 */
		ts_modes[0] = sizeof(ts_modes) / sizeof(ULONG);
		ret = PacketGetTimestampModes(adapter, ts_modes);
		if (!ret) {
			/*
			 * OK, it failed.  Did it fail with
			 * ERROR_MORE_DATA?
			 */
			error = GetLastError();
			if (error != ERROR_MORE_DATA) {
				/*
				 * No, did it fail with ERROR_INVALID_FUNCTION?
				 */
				if (error == ERROR_INVALID_FUNCTION) {
					/*
					 * This is probably due to
					 * the driver with which Packet.dll
					 * communicates being older, or
					 * being a WinPcap driver, so
					 * that it doesn't support
					 * BIOCGTIMESTAMPMODES.
					 *
					 * Tell the user to try uninstalling
					 * Npcap - and WinPcap if installed -
					 * and re-installing it, to flush
					 * out all older drivers.
					 */
					snprintf(ebuf, PCAP_ERRBUF_SIZE,
					    "PacketGetTimestampModes() failed with ERROR_INVALID_FUNCTION; try uninstalling Npcap, and WinPcap if installed, and re-installing it from npcap.com");
					status = -1;
					break;
				}

				/*
				 * No, some other error.  Fail.
				 */
				pcapint_fmt_errmsg_for_win32_err(ebuf,
				    PCAP_ERRBUF_SIZE, error,
				    "Error calling PacketGetTimestampModes");
				status = -1;
				break;
			}

			/*
			 * Yes, so we now know how many types to fetch.
			 *
			 * The buffer needs to have one ULONG for the
			 * count and num_ts_modes ULONGs for the
			 * num_ts_modes time stamp types.
			 */
			num_ts_modes = ts_modes[0];
			modes = (ULONG *)malloc((1 + num_ts_modes) * sizeof(ULONG));
			if (modes == NULL) {
				/* Out of memory. */
				pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE, errno, "malloc");
				status = -1;
				break;
			}
			modes[0] = 1 + num_ts_modes;
			if (!PacketGetTimestampModes(adapter, modes)) {
				pcapint_fmt_errmsg_for_win32_err(ebuf,
						PCAP_ERRBUF_SIZE, GetLastError(),
						"Error calling PacketGetTimestampModes");
				status = -1;
				break;
			}
			if (modes[0] != num_ts_modes) {
				snprintf(ebuf, PCAP_ERRBUF_SIZE,
						"First PacketGetTimestampModes() call gives %lu modes, second call gives %lu modes",
						num_ts_modes, modes[0]);
				status = -1;
				break;
			}
		}
		else {
			modes = ts_modes;
			num_ts_modes = ts_modes[0];
		}

		/* If the driver reports no modes supported *and*
		 * ERROR_MORE_DATA, something is seriously wrong.
		 * We *could* ignore the error and continue without supporting
		 * settable timestamp modes, but that would hide a bug.
		 */
		if (modes[0] == 0) {
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
			    "PacketGetTimestampModes() reports 0 modes supported.");
			status = -1;
			break;
		}

		/*
		 * Allocate a buffer big enough for
		 * PCAP_TSTAMP_HOST (default) plus
		 * the explicitly specified modes.
		 */
		p->tstamp_type_list = malloc((1 + num_ts_modes) * sizeof(u_int));
		if (p->tstamp_type_list == NULL) {
			pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE, errno, "malloc");
			status = -1;
			break;
		}
		u_int num_ts_types = 0;
		p->tstamp_type_list[num_ts_types] =
		    PCAP_TSTAMP_HOST;
		num_ts_types++;
		for (ULONG i = 0; i < num_ts_modes; i++) {
			switch (modes[i + 1]) {

			case TIMESTAMPMODE_SINGLE_SYNCHRONIZATION:
				/*
				 * Better than low-res,
				 * but *not* synchronized
				 * with the OS clock.
				 */
				p->tstamp_type_list[num_ts_types] =
				    PCAP_TSTAMP_HOST_HIPREC_UNSYNCED;
				num_ts_types++;
				break;

			case TIMESTAMPMODE_QUERYSYSTEMTIME:
				/*
				 * Low-res, but synchronized
				 * with the OS clock.
				 */
				p->tstamp_type_list[num_ts_types] =
				    PCAP_TSTAMP_HOST_LOWPREC;
				num_ts_types++;
				break;

			case TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE:
				/*
				 * High-res, and synchronized
				 * with the OS clock.
				 */
				p->tstamp_type_list[num_ts_types] =
				    PCAP_TSTAMP_HOST_HIPREC;
				num_ts_types++;
				break;

			default:
				/*
				 * Unknown, so we can't
				 * report it.
				 */
				break;
			}
		}
		p->tstamp_type_count = num_ts_types;
	} while (0);

	/* Clean up temporary allocations */
	if (device_copy != NULL) {
		free(device_copy);
	}
	if (modes != NULL && modes != ts_modes) {
		free(modes);
	}
	if (adapter != NULL) {
		PacketCloseAdapter(adapter);
	}

	return status;
}
#else /* HAVE_PACKET_GET_TIMESTAMP_MODES */
static int
get_ts_types(const char *device _U_, pcap_t *p _U_, char *ebuf _U_)
{
	/*
	 * Nothing to fetch, so it always "succeeds".
	 */
	return 0;
}
#endif /* HAVE_PACKET_GET_TIMESTAMP_MODES */

pcap_t *
pcapint_create_interface(const char *device _U_, char *ebuf)
{
	pcap_t *p;

	p = PCAP_CREATE_COMMON(ebuf, struct pcap_win);
	if (p == NULL)
		return (NULL);

	p->activate_op = pcap_activate_npf;
	p->can_set_rfmon_op = pcap_can_set_rfmon_npf;

	if (get_ts_types(device, p, ebuf) == -1) {
		pcap_close(p);
		return (NULL);
	}
	return (p);
}

static int
pcap_setfilter_npf(pcap_t *p, struct bpf_program *fp)
{
	struct pcap_win *pw = p->priv;

	if(PacketSetBpf(pw->adapter,fp)==FALSE){
		/*
		 * Kernel filter not installed.
		 *
		 * XXX - we don't know whether this failed because:
		 *
		 *  the kernel rejected the filter program as invalid,
		 *  in which case we should fall back on userland
		 *  filtering;
		 *
		 *  the kernel rejected the filter program as too big,
		 *  in which case we should again fall back on
		 *  userland filtering;
		 *
		 *  there was some other problem, in which case we
		 *  should probably report an error.
		 *
		 * For NPF devices, the Win32 status will be
		 * STATUS_INVALID_DEVICE_REQUEST for invalid
		 * filters, but I don't know what it'd be for
		 * other problems, and for some other devices
		 * it might not be set at all.
		 *
		 * So we just fall back on userland filtering in
		 * all cases.
		 */

		/*
		 * pcapint_install_bpf_program() validates the program.
		 *
		 * XXX - what if we already have a filter in the kernel?
		 */
		if (pcapint_install_bpf_program(p, fp) < 0)
			return (-1);
		pw->filtering_in_kernel = 0;	/* filtering in userland */
		return (0);
	}

	/*
	 * It worked.
	 */
	pw->filtering_in_kernel = 1;	/* filtering in the kernel */

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
 * We filter at user level, since the kernel driver doesn't process the packets
 */
static int
pcap_setfilter_win32_dag(pcap_t *p, struct bpf_program *fp) {

	if(!fp)
	{
		pcapint_strlcpy(p->errbuf, "setfilter: No filter specified", sizeof(p->errbuf));
		return (-1);
	}

	/* Install a user level filter */
	if (pcapint_install_bpf_program(p, fp) < 0)
		return (-1);

	return (0);
}

static int
pcap_getnonblock_npf(pcap_t *p)
{
	struct pcap_win *pw = p->priv;

	/*
	 * XXX - if there were a PacketGetReadTimeout() call, we
	 * would use it, and return 1 if the timeout is -1
	 * and 0 otherwise.
	 */
	return (pw->nonblock);
}

static int
pcap_setnonblock_npf(pcap_t *p, int nonblock)
{
	struct pcap_win *pw = p->priv;
	int newtimeout;

	if (nonblock) {
		/*
		 * Set the packet buffer timeout to -1 for non-blocking
		 * mode.
		 */
		newtimeout = -1;
	} else {
		/*
		 * Restore the timeout set when the device was opened.
		 * (Note that this may be -1, in which case we're not
		 * really leaving non-blocking mode.  However, although
		 * the timeout argument to pcap_set_timeout() and
		 * pcap_open_live() is an int, you're not supposed to
		 * supply a negative value, so that "shouldn't happen".)
		 */
		newtimeout = p->opt.timeout;
	}
	if (!PacketSetReadTimeout(pw->adapter, newtimeout)) {
		pcapint_fmt_errmsg_for_win32_err(p->errbuf, PCAP_ERRBUF_SIZE,
		    GetLastError(), "PacketSetReadTimeout");
		return (-1);
	}
	pw->nonblock = (newtimeout == -1);
	return (0);
}

static int
pcap_add_if_npf(pcap_if_list_t *devlistp, char *name, bpf_u_int32 flags,
    const char *description, char *errbuf)
{
	pcap_if_t *curdev;
	npf_if_addr if_addrs[MAX_NETWORK_ADDRESSES];
	LONG if_addr_size;
	int res = 0;

	if_addr_size = MAX_NETWORK_ADDRESSES;

	/*
	 * Add an entry for this interface, with no addresses.
	 */
	curdev = pcapint_add_dev(devlistp, name, flags, description, errbuf);
	if (curdev == NULL) {
		/*
		 * Failure.
		 */
		return (-1);
	}

	/*
	 * Get the list of addresses for the interface.
	 */
	if (!PacketGetNetInfoEx((void *)name, if_addrs, &if_addr_size)) {
		/*
		 * Failure.
		 *
		 * We don't return an error, because this can happen with
		 * NdisWan interfaces, and we want to supply them even
		 * if we can't supply their addresses.
		 *
		 * We return an entry with an empty address list.
		 */
		return (0);
	}

	/*
	 * Now add the addresses.
	 */
	while (if_addr_size-- > 0) {
		/*
		 * "curdev" is an entry for this interface; add an entry for
		 * this address to its list of addresses.
		 */
		res = pcapint_add_addr_to_dev(curdev,
		    (struct sockaddr *)&if_addrs[if_addr_size].IPAddress,
		    sizeof (struct sockaddr_storage),
		    (struct sockaddr *)&if_addrs[if_addr_size].SubnetMask,
		    sizeof (struct sockaddr_storage),
		    (struct sockaddr *)&if_addrs[if_addr_size].Broadcast,
		    sizeof (struct sockaddr_storage),
		    NULL,
		    0,
		    errbuf);
		if (res == -1) {
			/*
			 * Failure.
			 */
			break;
		}
	}

	return (res);
}

static int
get_if_flags(const char *name, bpf_u_int32 *flags, char *errbuf)
{
	char *name_copy;
	ADAPTER *adapter;
	int status;
	size_t len;
	NDIS_HARDWARE_STATUS hardware_status;
#ifdef OID_GEN_PHYSICAL_MEDIUM
	NDIS_PHYSICAL_MEDIUM phys_medium;
	bpf_u_int32 gen_physical_medium_oids[] = {
  #ifdef OID_GEN_PHYSICAL_MEDIUM_EX
		OID_GEN_PHYSICAL_MEDIUM_EX,
  #endif
		OID_GEN_PHYSICAL_MEDIUM
	};
#define N_GEN_PHYSICAL_MEDIUM_OIDS	(sizeof gen_physical_medium_oids / sizeof gen_physical_medium_oids[0])
	size_t i;
#endif /* OID_GEN_PHYSICAL_MEDIUM */
#ifdef OID_GEN_LINK_STATE
	NDIS_LINK_STATE link_state;
#endif
	int connect_status;

	if (*flags & PCAP_IF_LOOPBACK) {
		/*
		 * Loopback interface, so the connection status doesn't
		 * apply. and it's not wireless (or wired, for that
		 * matter...).  We presume it's up and running.
		 */
		*flags |= PCAP_IF_UP | PCAP_IF_RUNNING | PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE;
		return (0);
	}

	/*
	 * We need to open the adapter to get this information.
	 *
	 * XXX - PacketOpenAdapter() takes a non-const pointer
	 * as an argument, so we make a copy of the argument and
	 * pass that to it.
	 */
	name_copy = strdup(name);
	adapter = PacketOpenAdapter(name_copy);
	free(name_copy);
	if (adapter == NULL) {
		/*
		 * Give up; if they try to open this device, it'll fail.
		 */
		return (0);
	}

#ifdef HAVE_AIRPCAP_API
	/*
	 * Airpcap.sys do not support the below 'OID_GEN_x' values.
	 * Just set these flags (and none of the '*flags' entered with).
	 */
	if (PacketGetAirPcapHandle(adapter)) {
		/*
		 * Must be "up" and "running" if the above if succeeded.
		 */
		*flags = PCAP_IF_UP | PCAP_IF_RUNNING;

		/*
		 * An airpcap device is a wireless device (duh!)
		 */
		*flags |= PCAP_IF_WIRELESS;

		/*
		 * A "network association state" makes no sense for airpcap.
		 */
		*flags |= PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE;
		PacketCloseAdapter(adapter);
		return (0);
	}
#endif

	/*
	 * Get the hardware status, and derive "up" and "running" from
	 * that.
	 */
	len = sizeof (hardware_status);
	status = oid_get_request(adapter, OID_GEN_HARDWARE_STATUS,
	    &hardware_status, &len, errbuf);
	if (status == 0) {
		switch (hardware_status) {

		case NdisHardwareStatusReady:
			/*
			 * "Available and capable of sending and receiving
			 * data over the wire", so up and running.
			 */
			*flags |= PCAP_IF_UP | PCAP_IF_RUNNING;
			break;

		case NdisHardwareStatusInitializing:
		case NdisHardwareStatusReset:
			/*
			 * "Initializing" or "Resetting", so up, but
			 * not running.
			 */
			*flags |= PCAP_IF_UP;
			break;

		case NdisHardwareStatusClosing:
		case NdisHardwareStatusNotReady:
			/*
			 * "Closing" or "Not ready", so neither up nor
			 * running.
			 */
			break;

		default:
			/*
			 * Unknown.
			 */
			break;
		}
	} else {
		/*
		 * Can't get the hardware status, so assume both up and
		 * running.
		 */
		*flags |= PCAP_IF_UP | PCAP_IF_RUNNING;
	}

	/*
	 * Get the network type.
	 */
#ifdef OID_GEN_PHYSICAL_MEDIUM
	/*
	 * Try the OIDs we have for this, in order.
	 */
	for (i = 0; i < N_GEN_PHYSICAL_MEDIUM_OIDS; i++) {
		len = sizeof (phys_medium);
		status = oid_get_request(adapter, gen_physical_medium_oids[i],
		    &phys_medium, &len, errbuf);
		if (status == 0) {
			/*
			 * Success.
			 */
			break;
		}
		/*
		 * Failed.  We can't determine whether it failed
		 * because that particular OID isn't supported
		 * or because some other problem occurred, so we
		 * just drive on and try the next OID.
		 */
	}
	if (status == 0) {
		/*
		 * We got the physical medium.
		 *
		 * XXX - we might want to check for NdisPhysicalMediumWiMax
		 * and NdisPhysicalMediumNative802_15_4 being
		 * part of the enum, and check for those in the "wireless"
		 * case.
		 */
DIAG_OFF_ENUM_SWITCH
		switch (phys_medium) {

		case NdisPhysicalMediumWirelessLan:
		case NdisPhysicalMediumWirelessWan:
		case NdisPhysicalMediumNative802_11:
		case NdisPhysicalMediumBluetooth:
		case NdisPhysicalMediumUWB:
		case NdisPhysicalMediumIrda:
			/*
			 * Wireless.
			 */
			*flags |= PCAP_IF_WIRELESS;
			break;

		default:
			/*
			 * Not wireless or unknown
			 */
			break;
		}
DIAG_ON_ENUM_SWITCH
	}
#endif

	/*
	 * Get the connection status.
	 */
#ifdef OID_GEN_LINK_STATE
	len = sizeof(link_state);
	status = oid_get_request(adapter, OID_GEN_LINK_STATE, &link_state,
	    &len, errbuf);
	if (status == 0) {
		/*
		 * NOTE: this also gives us the receive and transmit
		 * link state.
		 */
		switch (link_state.MediaConnectState) {

		case MediaConnectStateConnected:
			/*
			 * It's connected.
			 */
			*flags |= PCAP_IF_CONNECTION_STATUS_CONNECTED;
			break;

		case MediaConnectStateDisconnected:
			/*
			 * It's disconnected.
			 */
			*flags |= PCAP_IF_CONNECTION_STATUS_DISCONNECTED;
			break;

		case MediaConnectStateUnknown:
		default:
			/*
			 * It's unknown whether it's connected or not.
			 */
			break;
		}
	}
#else
	/*
	 * OID_GEN_LINK_STATE isn't supported because it's not in our SDK.
	 */
	status = -1;
#endif
	if (status == -1) {
		/*
		 * OK, OID_GEN_LINK_STATE didn't work, try
		 * OID_GEN_MEDIA_CONNECT_STATUS.
		 */
		status = oid_get_request(adapter, OID_GEN_MEDIA_CONNECT_STATUS,
		    &connect_status, &len, errbuf);
		if (status == 0) {
			switch (connect_status) {

			case NdisMediaStateConnected:
				/*
				 * It's connected.
				 */
				*flags |= PCAP_IF_CONNECTION_STATUS_CONNECTED;
				break;

			case NdisMediaStateDisconnected:
				/*
				 * It's disconnected.
				 */
				*flags |= PCAP_IF_CONNECTION_STATUS_DISCONNECTED;
				break;
			}
		}
	}
	PacketCloseAdapter(adapter);
	return (0);
}

int
pcapint_platform_finddevs(pcap_if_list_t *devlistp, char *errbuf)
{
	int ret = 0;
	const char *desc;
	char *AdaptersName;
	ULONG NameLength;
	char *name;

	/*
	 * Find out how big a buffer we need.
	 *
	 * This call should always return FALSE; if the error is
	 * ERROR_INSUFFICIENT_BUFFER, NameLength will be set to
	 * the size of the buffer we need, otherwise there's a
	 * problem, and NameLength should be set to 0.
	 *
	 * It shouldn't require NameLength to be set, but,
	 * at least as of WinPcap 4.1.3, it checks whether
	 * NameLength is big enough before it checks for a
	 * NULL buffer argument, so, while it'll still do
	 * the right thing if NameLength is uninitialized and
	 * whatever junk happens to be there is big enough
	 * (because the pointer argument will be null), it's
	 * still reading an uninitialized variable.
	 */
	NameLength = 0;
	if (!PacketGetAdapterNames(NULL, &NameLength))
	{
		DWORD last_error = GetLastError();

		if (last_error != ERROR_INSUFFICIENT_BUFFER)
		{
			pcapint_fmt_errmsg_for_win32_err(errbuf, PCAP_ERRBUF_SIZE,
			    last_error, "PacketGetAdapterNames");
			return (-1);
		}
	}

	if (NameLength <= 0)
		return 0;
	AdaptersName = (char*) malloc(NameLength);
	if (AdaptersName == NULL)
	{
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "Cannot allocate enough memory to list the adapters.");
		return (-1);
	}

	if (!PacketGetAdapterNames(AdaptersName, &NameLength)) {
		pcapint_fmt_errmsg_for_win32_err(errbuf, PCAP_ERRBUF_SIZE,
		    GetLastError(), "PacketGetAdapterNames");
		free(AdaptersName);
		return (-1);
	}

	/*
	 * "PacketGetAdapterNames()" returned a list of
	 * null-terminated ASCII interface name strings,
	 * terminated by a null string, followed by a list
	 * of null-terminated ASCII interface description
	 * strings, terminated by a null string.
	 * This means there are two ASCII nulls at the end
	 * of the first list.
	 *
	 * Find the end of the first list; that's the
	 * beginning of the second list.
	 */
	desc = &AdaptersName[0];
	while (*desc != '\0' || *(desc + 1) != '\0')
		desc++;

	/*
	 * Found it - "desc" points to the first of the two
	 * nulls at the end of the list of names, so the
	 * first byte of the list of descriptions is two bytes
	 * after it.
	 */
	desc += 2;

	/*
	 * Loop over the elements in the first list.
	 */
	name = &AdaptersName[0];
	while (*name != '\0') {
		bpf_u_int32 flags = 0;

#ifdef HAVE_AIRPCAP_API
		/*
		 * Is this an AirPcap device?
		 * If so, ignore it; it'll get added later, by the
		 * AirPcap code.
		 */
		if (device_is_airpcap(name, errbuf) == 1) {
			name += strlen(name) + 1;
			desc += strlen(desc) + 1;
			continue;
		}
#endif

#ifdef HAVE_PACKET_IS_LOOPBACK_ADAPTER
		/*
		 * Is this a loopback interface?
		 */
		if (PacketIsLoopbackAdapter(name)) {
			/* Yes */
			flags |= PCAP_IF_LOOPBACK;
		}
#endif
		/*
		 * Get additional flags.
		 */
		if (get_if_flags(name, &flags, errbuf) == -1) {
			/*
			 * Failure.
			 */
			ret = -1;
			break;
		}

		/*
		 * Add an entry for this interface.
		 */
		if (pcap_add_if_npf(devlistp, name, flags, desc,
		    errbuf) == -1) {
			/*
			 * Failure.
			 */
			ret = -1;
			break;
		}
		name += strlen(name) + 1;
		desc += strlen(desc) + 1;
	}

	free(AdaptersName);
	return (ret);
}

/*
 * Return the name of a network interface attached to the system, or NULL
 * if none can be found.  The interface must be configured up; the
 * lowest unit number is preferred; loopback is ignored.
 *
 * In the best of all possible worlds, this would be the same as on
 * UN*X, but there may be software that expects this to return a
 * full list of devices after the first device.
 */
#define ADAPTERSNAME_LEN	8192
char *
pcap_lookupdev(char *errbuf)
{
	DWORD dwVersion;
	DWORD dwWindowsMajorVersion;

	/*
	 * We disable this in "new API" mode, because 1) in WinPcap/Npcap,
	 * it may return UTF-16 strings, for backwards-compatibility
	 * reasons, and we're also disabling the hack to make that work,
	 * for not-going-past-the-end-of-a-string reasons, and 2) we
	 * want its behavior to be consistent.
	 *
	 * In addition, it's not thread-safe, so we've marked it as
	 * deprecated.
	 */
	if (pcapint_new_api) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "pcap_lookupdev() is deprecated and is not supported in programs calling pcap_init()");
		return (NULL);
	}

/* disable MSVC's GetVersion() deprecated warning here */
DIAG_OFF_DEPRECATION
	dwVersion = GetVersion();	/* get the OS version */
DIAG_ON_DEPRECATION
	dwWindowsMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));

	if (dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4) {
		/*
		 * Windows 95, 98, ME.
		 */
		ULONG NameLength = ADAPTERSNAME_LEN;
		static char AdaptersName[ADAPTERSNAME_LEN];

		if (PacketGetAdapterNames(AdaptersName,&NameLength) )
			return (AdaptersName);
		else
			return NULL;
	} else {
		/*
		 * Windows NT (NT 4.0 and later).
		 * Convert the names to Unicode for backward compatibility.
		 */
		ULONG NameLength = ADAPTERSNAME_LEN;
		static WCHAR AdaptersName[ADAPTERSNAME_LEN];
		size_t BufferSpaceLeft;
		char *tAstr;
		WCHAR *Unameptr;
		char *Adescptr;
		size_t namelen, i;
		WCHAR *TAdaptersName = (WCHAR*)malloc(ADAPTERSNAME_LEN * sizeof(WCHAR));
		int NAdapts = 0;

		if(TAdaptersName == NULL)
		{
			(void)snprintf(errbuf, PCAP_ERRBUF_SIZE, "memory allocation failure");
			return NULL;
		}

		if ( !PacketGetAdapterNames((PTSTR)TAdaptersName,&NameLength) )
		{
			pcapint_fmt_errmsg_for_win32_err(errbuf, PCAP_ERRBUF_SIZE,
			    GetLastError(), "PacketGetAdapterNames");
			free(TAdaptersName);
			return NULL;
		}


		BufferSpaceLeft = ADAPTERSNAME_LEN * sizeof(WCHAR);
		tAstr = (char*)TAdaptersName;
		Unameptr = AdaptersName;

		/*
		 * Convert the device names to Unicode into AdapterName.
		 */
		do {
			/*
			 * Length of the name, including the terminating
			 * NUL.
			 */
			namelen = strlen(tAstr) + 1;

			/*
			 * Do we have room for the name in the Unicode
			 * buffer?
			 */
			if (BufferSpaceLeft < namelen * sizeof(WCHAR)) {
				/*
				 * No.
				 */
				goto quit;
			}
			BufferSpaceLeft -= namelen * sizeof(WCHAR);

			/*
			 * Copy the name, converting ASCII to Unicode.
			 * namelen includes the NUL, so we copy it as
			 * well.
			 */
			for (i = 0; i < namelen; i++)
				*Unameptr++ = *tAstr++;

			/*
			 * Count this adapter.
			 */
			NAdapts++;
		} while (namelen != 1);

		/*
		 * Copy the descriptions, but don't convert them from
		 * ASCII to Unicode.
		 */
		Adescptr = (char *)Unameptr;
		while(NAdapts--)
		{
			size_t desclen;

			desclen = strlen(tAstr) + 1;

			/*
			 * Do we have room for the name in the Unicode
			 * buffer?
			 */
			if (BufferSpaceLeft < desclen) {
				/*
				 * No.
				 */
				goto quit;
			}

			/*
			 * Just copy the ASCII string.
			 * namelen includes the NUL, so we copy it as
			 * well.
			 */
			memcpy(Adescptr, tAstr, desclen);
			Adescptr += desclen;
			tAstr += desclen;
			BufferSpaceLeft -= desclen;
		}

	quit:
		free(TAdaptersName);
		return (char *)(AdaptersName);
	}
}

/*
 * We can't use the same code that we use on UN*X, as that's doing
 * UN*X-specific calls.
 *
 * We don't just fetch the entire list of devices, search for the
 * particular device, and use its first IPv4 address, as that's too
 * much work to get just one device's netmask.
 */
int
pcap_lookupnet(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp,
    char *errbuf)
{
	/*
	 * We need only the first IPv4 address, so we must scan the array returned by PacketGetNetInfo()
	 * in order to skip non IPv4 (i.e. IPv6 addresses)
	 */
	npf_if_addr if_addrs[MAX_NETWORK_ADDRESSES];
	LONG if_addr_size = MAX_NETWORK_ADDRESSES;
	struct sockaddr_in *t_addr;
	LONG i;

	if (!PacketGetNetInfoEx((void *)device, if_addrs, &if_addr_size)) {
		*netp = *maskp = 0;
		return (0);
	}

	for(i = 0; i < if_addr_size; i++)
	{
		if(if_addrs[i].IPAddress.ss_family == AF_INET)
		{
			t_addr = (struct sockaddr_in *) &(if_addrs[i].IPAddress);
			*netp = t_addr->sin_addr.S_un.S_addr;
			t_addr = (struct sockaddr_in *) &(if_addrs[i].SubnetMask);
			*maskp = t_addr->sin_addr.S_un.S_addr;

			*netp &= *maskp;
			return (0);
		}

	}

	*netp = *maskp = 0;
	return (0);
}

static const char *pcap_lib_version_string;

#ifdef HAVE_VERSION_H
/*
 * libpcap being built for Windows, as part of a WinPcap/Npcap source
 * tree.  Include version.h from that source tree to get the WinPcap/Npcap
 * version.
 *
 * XXX - it'd be nice if we could somehow generate the WinPcap/Npcap version
 * number when building as part of WinPcap/Npcap.  (It'd be nice to do so
 * for the packet.dll version number as well.)
 */
#include "../../version.h"

static const char pcap_version_string[] =
	WINPCAP_PRODUCT_NAME " version " WINPCAP_VER_STRING ", based on " PCAP_VERSION_STRING;

const char *
pcap_lib_version(void)
{
	if (pcap_lib_version_string == NULL) {
		/*
		 * Generate the version string.
		 */
		const char *packet_version_string = PacketGetVersion();

		if (strcmp(WINPCAP_VER_STRING, packet_version_string) == 0) {
			/*
			 * WinPcap/Npcap version string and packet.dll version
			 * string are the same; just report the WinPcap/Npcap
			 * version.
			 */
			pcap_lib_version_string = pcap_version_string;
		} else {
			/*
			 * WinPcap/Npcap version string and packet.dll version
			 * string are different; that shouldn't be the
			 * case (the two libraries should come from the
			 * same version of WinPcap/Npcap), so we report both
			 * versions.
			 */
			char *full_pcap_version_string;

			if (pcapint_asprintf(&full_pcap_version_string,
			    WINPCAP_PRODUCT_NAME " version " WINPCAP_VER_STRING " (packet.dll version %s), based on " PCAP_VERSION_STRING,
			    packet_version_string) != -1) {
				/* Success */
				pcap_lib_version_string = full_pcap_version_string;
			}
		}
	}
	return (pcap_lib_version_string);
}

#else /* HAVE_VERSION_H */

/*
 * libpcap being built for Windows, not as part of a WinPcap/Npcap source
 * tree.
 */
const char *
pcap_lib_version(void)
{
	if (pcap_lib_version_string == NULL) {
		/*
		 * Generate the version string.  Report the packet.dll
		 * version.
		 */
		char *full_pcap_version_string;

		if (pcapint_asprintf(&full_pcap_version_string,
		    PCAP_VERSION_STRING " (packet.dll version %s)",
		    PacketGetVersion()) != -1) {
			/* Success */
			pcap_lib_version_string = full_pcap_version_string;
		}
	}
	return (pcap_lib_version_string);
}
#endif /* HAVE_VERSION_H */
