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

#include "pcap-int.h"

#include <airpcap.h>

#include "pcap-airpcap.h"

/* Default size of the buffer we allocate in userland. */
#define	AIRPCAP_DEFAULT_USER_BUFFER_SIZE 256000

/* Default size of the buffer for the AirPcap adapter. */
#define	AIRPCAP_DEFAULT_KERNEL_BUFFER_SIZE 1000000

//
// We load the AirPcap DLL dynamically, so that the code will
// work whether you have it installed or not, and there don't
// have to be two different versions of the library, one linked
// to the AirPcap library and one not linked to it.
//
static pcap_code_handle_t airpcap_lib;

typedef PCHAR (*AirpcapGetLastErrorHandler)(PAirpcapHandle);
typedef BOOL (*AirpcapGetDeviceListHandler)(PAirpcapDeviceDescription *, PCHAR);
typedef VOID (*AirpcapFreeDeviceListHandler)(PAirpcapDeviceDescription);
typedef PAirpcapHandle (*AirpcapOpenHandler)(PCHAR, PCHAR);
typedef VOID (*AirpcapCloseHandler)(PAirpcapHandle);
typedef BOOL (*AirpcapSetDeviceMacFlagsHandler)(PAirpcapHandle, UINT);
typedef BOOL (*AirpcapSetLinkTypeHandler)(PAirpcapHandle, AirpcapLinkType);
typedef BOOL (*AirpcapGetLinkTypeHandler)(PAirpcapHandle, PAirpcapLinkType);
typedef BOOL (*AirpcapSetKernelBufferHandler)(PAirpcapHandle, UINT);
typedef BOOL (*AirpcapSetFilterHandler)(PAirpcapHandle, PVOID, UINT);
typedef BOOL (*AirpcapSetMinToCopyHandler)(PAirpcapHandle, UINT);
typedef BOOL (*AirpcapGetReadEventHandler)(PAirpcapHandle, HANDLE *);
typedef BOOL (*AirpcapReadHandler)(PAirpcapHandle, PBYTE, UINT, PUINT);
typedef BOOL (*AirpcapWriteHandler)(PAirpcapHandle, PCHAR, ULONG);
typedef BOOL (*AirpcapGetStatsHandler)(PAirpcapHandle, PAirpcapStats);

static AirpcapGetLastErrorHandler p_AirpcapGetLastError;
static AirpcapGetDeviceListHandler p_AirpcapGetDeviceList;
static AirpcapFreeDeviceListHandler p_AirpcapFreeDeviceList;
static AirpcapOpenHandler p_AirpcapOpen;
static AirpcapCloseHandler p_AirpcapClose;
static AirpcapSetDeviceMacFlagsHandler p_AirpcapSetDeviceMacFlags;
static AirpcapSetLinkTypeHandler p_AirpcapSetLinkType;
static AirpcapGetLinkTypeHandler p_AirpcapGetLinkType;
static AirpcapSetKernelBufferHandler p_AirpcapSetKernelBuffer;
static AirpcapSetFilterHandler p_AirpcapSetFilter;
static AirpcapSetMinToCopyHandler p_AirpcapSetMinToCopy;
static AirpcapGetReadEventHandler p_AirpcapGetReadEvent;
static AirpcapReadHandler p_AirpcapRead;
static AirpcapWriteHandler p_AirpcapWrite;
static AirpcapGetStatsHandler p_AirpcapGetStats;

typedef enum LONG
{
	AIRPCAP_API_UNLOADED = 0,
	AIRPCAP_API_LOADED,
	AIRPCAP_API_CANNOT_LOAD,
	AIRPCAP_API_LOADING
} AIRPCAP_API_LOAD_STATUS;

static AIRPCAP_API_LOAD_STATUS	airpcap_load_status;

/*
 * NOTE: this function should be called by the pcap functions that can
 *       theoretically deal with the AirPcap library for the first time,
 *       namely listing the adapters and creating a pcap_t for an adapter.
 *       All the other ones (activate, close, read, write, set parameters)
 *       work on a pcap_t for an AirPcap device, meaning we've already
 *       created the pcap_t and thus have loaded the functions, so we do
 *       not need to call this function.
 */
static AIRPCAP_API_LOAD_STATUS
load_airpcap_functions(void)
{
	AIRPCAP_API_LOAD_STATUS current_status;

	/*
	 * We don't use a mutex because there's no place that
	 * we can guarantee we'll be called before any threads
	 * other than the main thread exists.  (For example,
	 * this might be a static library, so we can't arrange
	 * to be called by DllMain(), and there's no guarantee
	 * that the application called pcap_init() - which is
	 * supposed to be called only from one thread - so
	 * we can't arrange to be called from it.)
	 *
	 * If nobody's tried to load it yet, mark it as
	 * loading; in any case, return the status before
	 * we modified it.
	 */
	current_status = InterlockedCompareExchange((LONG *)&airpcap_load_status,
	    AIRPCAP_API_LOADING, AIRPCAP_API_UNLOADED);

	/*
	 * If the status was AIRPCAP_API_UNLOADED, we've set it
	 * to AIRPCAP_API_LOADING, because we're going to be
	 * the ones to load the library but current_status is
	 * AIRPCAP_API_UNLOADED.
	 *
	 * if it was AIRPCAP_API_LOADING, meaning somebody else
	 * was trying to load it, spin until they finish and
	 * set the status to a value reflecting whether they
	 * succeeded.
	 */
	while (current_status == AIRPCAP_API_LOADING) {
		current_status = InterlockedCompareExchange((LONG*)&airpcap_load_status,
		    AIRPCAP_API_LOADING, AIRPCAP_API_LOADING);
		Sleep(10);
	}

	/*
	 * At this point, current_status is either:
	 *
	 *	AIRPCAP_API_LOADED, in which case another thread
	 *	loaded the library, so we're done;
	 *
	 *	AIRPCAP_API_CANNOT_LOAD, in which another thread
	 *	tried and failed to load the library, so we're
	 *	done - we won't try it ourselves;
	 *
	 *	AIRPCAP_API_LOADING, in which case *we're* the
	 *	ones loading it, and should now try to do so.
	 */
	if (current_status == AIRPCAP_API_LOADED)
		return AIRPCAP_API_LOADED;

	if (current_status == AIRPCAP_API_CANNOT_LOAD)
		return AIRPCAP_API_CANNOT_LOAD;

	/*
	 * Start out assuming we can't load it.
	 */
	current_status = AIRPCAP_API_CANNOT_LOAD;

	airpcap_lib = pcapint_load_code("airpcap.dll");
	if (airpcap_lib != NULL) {
		/*
		 * OK, we've loaded the library; now try to find the
		 * functions we need in it.
		 */
		p_AirpcapGetLastError = (AirpcapGetLastErrorHandler) pcapint_find_function(airpcap_lib, "AirpcapGetLastError");
		p_AirpcapGetDeviceList = (AirpcapGetDeviceListHandler) pcapint_find_function(airpcap_lib, "AirpcapGetDeviceList");
		p_AirpcapFreeDeviceList = (AirpcapFreeDeviceListHandler) pcapint_find_function(airpcap_lib, "AirpcapFreeDeviceList");
		p_AirpcapOpen = (AirpcapOpenHandler) pcapint_find_function(airpcap_lib, "AirpcapOpen");
		p_AirpcapClose = (AirpcapCloseHandler) pcapint_find_function(airpcap_lib, "AirpcapClose");
		p_AirpcapSetDeviceMacFlags = (AirpcapSetDeviceMacFlagsHandler) pcapint_find_function(airpcap_lib, "AirpcapSetDeviceMacFlags");
		p_AirpcapSetLinkType = (AirpcapSetLinkTypeHandler) pcapint_find_function(airpcap_lib, "AirpcapSetLinkType");
		p_AirpcapGetLinkType = (AirpcapGetLinkTypeHandler) pcapint_find_function(airpcap_lib, "AirpcapGetLinkType");
		p_AirpcapSetKernelBuffer = (AirpcapSetKernelBufferHandler) pcapint_find_function(airpcap_lib, "AirpcapSetKernelBuffer");
		p_AirpcapSetFilter = (AirpcapSetFilterHandler) pcapint_find_function(airpcap_lib, "AirpcapSetFilter");
		p_AirpcapSetMinToCopy = (AirpcapSetMinToCopyHandler) pcapint_find_function(airpcap_lib, "AirpcapSetMinToCopy");
		p_AirpcapGetReadEvent = (AirpcapGetReadEventHandler) pcapint_find_function(airpcap_lib, "AirpcapGetReadEvent");
		p_AirpcapRead = (AirpcapReadHandler) pcapint_find_function(airpcap_lib, "AirpcapRead");
		p_AirpcapWrite = (AirpcapWriteHandler) pcapint_find_function(airpcap_lib, "AirpcapWrite");
		p_AirpcapGetStats = (AirpcapGetStatsHandler) pcapint_find_function(airpcap_lib, "AirpcapGetStats");

		//
		// Make sure that we found everything
		//
		if (p_AirpcapGetLastError != NULL &&
		    p_AirpcapGetDeviceList != NULL &&
		    p_AirpcapFreeDeviceList != NULL &&
		    p_AirpcapOpen != NULL &&
		    p_AirpcapClose != NULL &&
		    p_AirpcapSetDeviceMacFlags != NULL &&
		    p_AirpcapSetLinkType != NULL &&
		    p_AirpcapGetLinkType != NULL &&
		    p_AirpcapSetKernelBuffer != NULL &&
		    p_AirpcapSetFilter != NULL &&
		    p_AirpcapSetMinToCopy != NULL &&
		    p_AirpcapGetReadEvent != NULL &&
		    p_AirpcapRead != NULL &&
		    p_AirpcapWrite != NULL &&
		    p_AirpcapGetStats != NULL) {
			/*
			 * We have all we need.
			 */
			current_status = AIRPCAP_API_LOADED;
		}
	}

	if (current_status != AIRPCAP_API_LOADED) {
		/*
		 * We failed; if we found the DLL, close the
		 * handle for it.
		 */
		if (airpcap_lib != NULL) {
			FreeLibrary(airpcap_lib);
			airpcap_lib = NULL;
		}
	}

	/*
	 * Now set the status appropriately - and atomically.
	 */
	InterlockedExchange((LONG *)&airpcap_load_status, current_status);

	return current_status;
}

/*
 * Private data for capturing on AirPcap devices.
 */
struct pcap_airpcap {
	PAirpcapHandle adapter;
	int filtering_in_kernel;
	int nonblock;
	int read_timeout;
	HANDLE read_event;
	struct pcap_stat stat;
};

static int
airpcap_setfilter(pcap_t *p, struct bpf_program *fp)
{
	struct pcap_airpcap *pa = p->priv;

	if (!p_AirpcapSetFilter(pa->adapter, fp->bf_insns,
	    fp->bf_len * sizeof(struct bpf_insn))) {
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
		 *  should probably report an error;
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
		pa->filtering_in_kernel = 0;	/* filtering in userland */
		return (0);
	}

	/*
	 * It worked.
	 */
	pa->filtering_in_kernel = 1;	/* filtering in the kernel */

	/*
	 * Discard any previously-received packets, as they might have
	 * passed whatever filter was formerly in effect, but might
	 * not pass this filter (BIOCSETF discards packets buffered
	 * in the kernel, so you can lose packets in any case).
	 */
	p->cc = 0;
	return (0);
}

static int
airpcap_set_datalink(pcap_t *p, int dlt)
{
	struct pcap_airpcap *pa = p->priv;
	AirpcapLinkType type;

	switch (dlt) {

	case DLT_IEEE802_11_RADIO:
		type = AIRPCAP_LT_802_11_PLUS_RADIO;
		break;

	case DLT_PPI:
		type = AIRPCAP_LT_802_11_PLUS_PPI;
		break;

	case DLT_IEEE802_11:
		type = AIRPCAP_LT_802_11;
		break;

	default:
		/* This can't happen; just return. */
		return (0);
	}
	if (!p_AirpcapSetLinkType(pa->adapter, type)) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "AirpcapSetLinkType() failed: %s",
		    p_AirpcapGetLastError(pa->adapter));
		return (-1);
	}
	p->linktype = dlt;
	return (0);
}

static int
airpcap_getnonblock(pcap_t *p)
{
	struct pcap_airpcap *pa = p->priv;

	return (pa->nonblock);
}

static int
airpcap_setnonblock(pcap_t *p, int nonblock)
{
	struct pcap_airpcap *pa = p->priv;
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
	pa->read_timeout = newtimeout;
	pa->nonblock = (newtimeout == -1);
	return (0);
}

static int
airpcap_stats(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_airpcap *pa = p->priv;
	AirpcapStats tas;

	/*
	 * Try to get statistics.
	 */
	if (!p_AirpcapGetStats(pa->adapter, &tas)) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "AirpcapGetStats() failed: %s",
		    p_AirpcapGetLastError(pa->adapter));
		return (-1);
	}

	ps->ps_drop = tas.Drops;
	ps->ps_recv = tas.Recvs;
	ps->ps_ifdrop = tas.IfDrops;

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
airpcap_stats_ex(pcap_t *p, int *pcap_stat_size)
{
	struct pcap_airpcap *pa = p->priv;
	AirpcapStats tas;

	*pcap_stat_size = sizeof (p->stat);

	/*
	 * Try to get statistics.
	 */
	if (!p_AirpcapGetStats(pa->adapter, &tas)) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "AirpcapGetStats() failed: %s",
		    p_AirpcapGetLastError(pa->adapter));
		return (NULL);
	}

	p->stat.ps_recv = tas.Recvs;
	p->stat.ps_drop = tas.Drops;
	p->stat.ps_ifdrop = tas.IfDrops;
	/*
	 * Just in case this is ever compiled for a target other than
	 * Windows, which is extremely unlikely at best.
	 */
#ifdef _WIN32
	p->stat.ps_capt = tas.Capt;
#endif
	return (&p->stat);
}

/* Set the dimension of the kernel-level capture buffer */
static int
airpcap_setbuff(pcap_t *p, int dim)
{
	struct pcap_airpcap *pa = p->priv;

	if (!p_AirpcapSetKernelBuffer(pa->adapter, dim)) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "AirpcapSetKernelBuffer() failed: %s",
		    p_AirpcapGetLastError(pa->adapter));
		return (-1);
	}
	return (0);
}

/* Set the driver working mode */
static int
airpcap_setmode(pcap_t *p, int mode)
{
	 if (mode != MODE_CAPT) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "Only MODE_CAPT is supported on an AirPcap adapter");
		return (-1);
	 }
	 return (0);
}

/*set the minimum amount of data that will release a read call*/
static int
airpcap_setmintocopy(pcap_t *p, int size)
{
	struct pcap_airpcap *pa = p->priv;

	if (!p_AirpcapSetMinToCopy(pa->adapter, size)) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "AirpcapSetMinToCopy() failed: %s",
		    p_AirpcapGetLastError(pa->adapter));
		return (-1);
	}
	return (0);
}

static HANDLE
airpcap_getevent(pcap_t *p)
{
	struct pcap_airpcap *pa = p->priv;

	return (pa->read_event);
}

static int
airpcap_oid_get_request(pcap_t *p, bpf_u_int32 oid _U_, void *data _U_,
    size_t *lenp _U_)
{
	snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
	    "Getting OID values is not supported on an AirPcap adapter");
	return (PCAP_ERROR);
}

static int
airpcap_oid_set_request(pcap_t *p, bpf_u_int32 oid _U_, const void *data _U_,
    size_t *lenp _U_)
{
	snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
	    "Setting OID values is not supported on an AirPcap adapter");
	return (PCAP_ERROR);
}

static u_int
airpcap_sendqueue_transmit(pcap_t *p, pcap_send_queue *queue _U_, int sync _U_)
{
	snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
	    "Cannot queue packets for transmission on an AirPcap adapter");
	return (0);
}

static int
airpcap_setuserbuffer(pcap_t *p, int size)
{
	unsigned char *new_buff;

	if (size <= 0) {
		/* Bogus parameter */
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "Error: invalid size %d",size);
		return (-1);
	}

	/* Allocate the buffer */
	new_buff = (unsigned char *)malloc(sizeof(char)*size);

	if (!new_buff) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "Error: not enough memory");
		return (-1);
	}

	free(p->buffer);

	p->buffer = new_buff;
	p->bufsize = size;

	return (0);
}

static int
airpcap_live_dump(pcap_t *p, char *filename _U_, int maxsize _U_,
    int maxpacks _U_)
{
	snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
	    "AirPcap adapters don't support live dump");
	return (-1);
}

static int
airpcap_live_dump_ended(pcap_t *p, int sync _U_)
{
	snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
	    "AirPcap adapters don't support live dump");
	return (-1);
}

static PAirpcapHandle
airpcap_get_airpcap_handle(pcap_t *p)
{
	struct pcap_airpcap *pa = p->priv;

	return (pa->adapter);
}

static int
airpcap_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	struct pcap_airpcap *pa = p->priv;
	int cc;
	int n;
	register u_char *bp, *ep;
	UINT bytes_read;
	u_char *datap;

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

		//
		// If we're not in non-blocking mode, wait for data to
		// arrive.
		//
		if (pa->read_timeout != -1) {
			WaitForSingleObject(pa->read_event,
			    (pa->read_timeout ==0 )? INFINITE: pa->read_timeout);
		}

		//
		// Read the data.
		// p_AirpcapRead doesn't block.
		//
		if (!p_AirpcapRead(pa->adapter, (PBYTE)p->buffer,
		    p->bufsize, &bytes_read)) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "AirpcapRead() failed: %s",
			    p_AirpcapGetLastError(pa->adapter));
			return (-1);
		}
		cc = bytes_read;
		bp = (u_char *)p->buffer;
	} else
		bp = p->bp;

	/*
	 * Loop through each packet.
	 *
	 * This assumes that a single buffer of packets will have
	 * <= INT_MAX packets, so the packet count doesn't overflow.
	 */
#define bhp ((AirpcapBpfHeader *)bp)
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

		caplen = bhp->Caplen;
		hdrlen = bhp->Hdrlen;
		datap = bp + hdrlen;
		/*
		 * Short-circuit evaluation: if using BPF filter
		 * in the AirPcap adapter, no need to do it now -
		 * we already know the packet passed the filter.
		 */
		if (pa->filtering_in_kernel ||
		    p->fcode.bf_insns == NULL ||
		    pcapint_filter(p->fcode.bf_insns, datap, bhp->Originallen, caplen)) {
			struct pcap_pkthdr pkthdr;

			pkthdr.ts.tv_sec = bhp->TsSec;
			pkthdr.ts.tv_usec = bhp->TsUsec;
			pkthdr.caplen = caplen;
			pkthdr.len = bhp->Originallen;
			(*callback)(user, &pkthdr, datap);
			bp += AIRPCAP_WORDALIGN(caplen + hdrlen);
			if (++n >= cnt && !PACKET_COUNT_IS_UNLIMITED(cnt)) {
				p->bp = bp;
				p->cc = (int)(ep - bp);
				return (n);
			}
		} else {
			/*
			 * Skip this packet.
			 */
			bp += AIRPCAP_WORDALIGN(caplen + hdrlen);
		}
	}
#undef bhp
	p->cc = 0;
	return (n);
}

static int
airpcap_inject(pcap_t *p, const void *buf, int size)
{
	struct pcap_airpcap *pa = p->priv;

	/*
	 * XXX - the second argument to AirpcapWrite() *should* have
	 * been declared as a const pointer - a write function that
	 * stomps on what it writes is *extremely* rude - but such
	 * is life.  We assume it is, in fact, not going to write on
	 * our buffer.
	 */
	if (!p_AirpcapWrite(pa->adapter, (void *)buf, size)) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "AirpcapWrite() failed: %s",
		    p_AirpcapGetLastError(pa->adapter));
		return (-1);
	}

	/*
	 * We assume it all got sent if "AirpcapWrite()" succeeded.
	 * "pcap_inject()" is expected to return the number of bytes
	 * sent.
	 */
	return (size);
}

static void
airpcap_cleanup(pcap_t *p)
{
	struct pcap_airpcap *pa = p->priv;

	if (pa->adapter != NULL) {
		p_AirpcapClose(pa->adapter);
		pa->adapter = NULL;
	}
	pcapint_cleanup_live_common(p);
}

static void
airpcap_breakloop(pcap_t *p)
{
	HANDLE read_event;

	pcapint_breakloop_common(p);
	struct pcap_airpcap *pa = p->priv;

	/* XXX - what if either of these fail? */
	/*
	 * XXX - will SetEvent() force a wakeup and, if so, will
	 * the AirPcap read code handle that sanely?
	 */
	if (!p_AirpcapGetReadEvent(pa->adapter, &read_event))
		return;
	SetEvent(read_event);
}

static int
airpcap_activate(pcap_t *p)
{
	struct pcap_airpcap *pa = p->priv;
	char *device = p->opt.device;
	char airpcap_errbuf[AIRPCAP_ERRBUF_SIZE];
	BOOL status;
	AirpcapLinkType link_type;

	pa->adapter = p_AirpcapOpen(device, airpcap_errbuf);
	if (pa->adapter == NULL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "%s", airpcap_errbuf);
		return (PCAP_ERROR);
	}

	/*
	 * Set monitor mode appropriately.
	 * Always turn off the "ACK frames sent to the card" mode.
	 */
	if (p->opt.rfmon) {
		status = p_AirpcapSetDeviceMacFlags(pa->adapter,
		    AIRPCAP_MF_MONITOR_MODE_ON);
	} else
		status = p_AirpcapSetDeviceMacFlags(pa->adapter,
		    AIRPCAP_MF_ACK_FRAMES_ON);
	if (!status) {
		p_AirpcapClose(pa->adapter);
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "AirpcapSetDeviceMacFlags() failed: %s",
		    p_AirpcapGetLastError(pa->adapter));
		return (PCAP_ERROR);
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

	/*
	 * If the buffer size wasn't explicitly set, default to
	 * AIRPCAP_DEFAULT_KERNEL_BUFFER_SIZE.
	 */
	if (p->opt.buffer_size == 0)
		p->opt.buffer_size = AIRPCAP_DEFAULT_KERNEL_BUFFER_SIZE;

	if (!p_AirpcapSetKernelBuffer(pa->adapter, p->opt.buffer_size)) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "AirpcapSetKernelBuffer() failed: %s",
		    p_AirpcapGetLastError(pa->adapter));
		goto bad;
	}

	if(!p_AirpcapGetReadEvent(pa->adapter, &pa->read_event)) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "AirpcapGetReadEvent() failed: %s",
		    p_AirpcapGetLastError(pa->adapter));
		goto bad;
	}

	/* Set the buffer size */
	p->bufsize = AIRPCAP_DEFAULT_USER_BUFFER_SIZE;
	p->buffer = malloc(p->bufsize);
	if (p->buffer == NULL) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		goto bad;
	}

	if (p->opt.immediate) {
		/* Tell the driver to copy the buffer as soon as data arrives. */
		if (!p_AirpcapSetMinToCopy(pa->adapter, 0)) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "AirpcapSetMinToCopy() failed: %s",
			    p_AirpcapGetLastError(pa->adapter));
			goto bad;
		}
	} else {
		/*
		 * Tell the driver to copy the buffer only if it contains
		 * at least 16K.
		 */
		if (!p_AirpcapSetMinToCopy(pa->adapter, 16000)) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "AirpcapSetMinToCopy() failed: %s",
			    p_AirpcapGetLastError(pa->adapter));
			goto bad;
		}
	}

	/*
	 * Find out what the default link-layer header type is,
	 * and set p->datalink to that.
	 *
	 * We don't force it to another value because there
	 * might be some programs using WinPcap/Npcap that,
	 * when capturing on AirPcap devices, assume the
	 * default value set with the AirPcap configuration
	 * program is what you get.
	 *
	 * The out-of-the-box default appears to be radiotap.
	 */
	if (!p_AirpcapGetLinkType(pa->adapter, &link_type)) {
		/* That failed. */
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "AirpcapGetLinkType() failed: %s",
		    p_AirpcapGetLastError(pa->adapter));
		goto bad;
	}
	switch (link_type) {

	case AIRPCAP_LT_802_11_PLUS_RADIO:
		p->linktype = DLT_IEEE802_11_RADIO;
		break;

	case AIRPCAP_LT_802_11_PLUS_PPI:
		p->linktype = DLT_PPI;
		break;

	case AIRPCAP_LT_802_11:
		p->linktype = DLT_IEEE802_11;
		break;

	case AIRPCAP_LT_UNKNOWN:
	default:
		/* OK, what? */
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "AirpcapGetLinkType() returned unknown link type %u",
		    link_type);
		goto bad;
	}

	/*
	 * Now provide a list of all the supported types; we
	 * assume they all work.  We put radiotap at the top,
	 * followed by PPI, followed by "no radio metadata".
	 */
	p->dlt_list = (u_int *) malloc(sizeof(u_int) * 3);
	if (p->dlt_list == NULL) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		goto bad;
	}
	p->dlt_list[0] = DLT_IEEE802_11_RADIO;
	p->dlt_list[1] = DLT_PPI;
	p->dlt_list[2] = DLT_IEEE802_11;
	p->dlt_count = 3;

	p->read_op = airpcap_read;
	p->inject_op = airpcap_inject;
	p->setfilter_op = airpcap_setfilter;
	p->setdirection_op = NULL;	/* Not implemented. */
	p->set_datalink_op = airpcap_set_datalink;
	p->getnonblock_op = airpcap_getnonblock;
	p->setnonblock_op = airpcap_setnonblock;
	p->breakloop_op = airpcap_breakloop;
	p->stats_op = airpcap_stats;
	p->stats_ex_op = airpcap_stats_ex;
	p->setbuff_op = airpcap_setbuff;
	p->setmode_op = airpcap_setmode;
	p->setmintocopy_op = airpcap_setmintocopy;
	p->getevent_op = airpcap_getevent;
	p->oid_get_request_op = airpcap_oid_get_request;
	p->oid_set_request_op = airpcap_oid_set_request;
	p->sendqueue_transmit_op = airpcap_sendqueue_transmit;
	p->setuserbuffer_op = airpcap_setuserbuffer;
	p->live_dump_op = airpcap_live_dump;
	p->live_dump_ended_op = airpcap_live_dump_ended;
	p->get_airpcap_handle_op = airpcap_get_airpcap_handle;
	p->cleanup_op = airpcap_cleanup;

	return (0);
 bad:
	airpcap_cleanup(p);
	return (PCAP_ERROR);
}

/*
 * Monitor mode is supported.
 */
static int
airpcap_can_set_rfmon(pcap_t *p)
{
	return (1);
}

int
device_is_airpcap(const char *device, char *ebuf)
{
	static const char airpcap_prefix[] = "\\\\.\\airpcap";

	/*
	 * We don't determine this by calling AirpcapGetDeviceList()
	 * and looking at the list, as that appears to be a costly
	 * operation.
	 *
	 * Instead, we just check whether it begins with "\\.\airpcap".
	 */
	if (strncmp(device, airpcap_prefix, sizeof airpcap_prefix - 1) == 0) {
		/*
		 * Yes, it's an AirPcap device.
		 */
		return (1);
	}

	/*
	 * No, it's not an AirPcap device.
	 */
	return (0);
}

pcap_t *
airpcap_create(const char *device, char *ebuf, int *is_ours)
{
	int ret;
	pcap_t *p;

	/*
	 * This can be called before we've tried loading the library,
	 * so do so if we haven't already tried to do so.
	 */
	if (load_airpcap_functions() != AIRPCAP_API_LOADED) {
		/*
		 * We assume this means that we don't have the AirPcap
		 * software installed, which probably means we don't
		 * have an AirPcap device.
		 *
		 * Don't treat that as an error.
		 */
		*is_ours = 0;
		return (NULL);
	}

	/*
	 * Is this an AirPcap device?
	 */
	ret = device_is_airpcap(device, ebuf);
	if (ret == 0) {
		/* No. */
		*is_ours = 0;
		return (NULL);
	}

	/*
	 * Yes.
	 */
	*is_ours = 1;
	p = PCAP_CREATE_COMMON(ebuf, struct pcap_airpcap);
	if (p == NULL)
		return (NULL);

	p->activate_op = airpcap_activate;
	p->can_set_rfmon_op = airpcap_can_set_rfmon;
	return (p);
}

/*
 * Add all AirPcap devices.
 */
int
airpcap_findalldevs(pcap_if_list_t *devlistp, char *errbuf)
{
	AirpcapDeviceDescription *airpcap_devices, *airpcap_device;
	char airpcap_errbuf[AIRPCAP_ERRBUF_SIZE];

	/*
	 * This can be called before we've tried loading the library,
	 * so do so if we haven't already tried to do so.
	 */
	if (load_airpcap_functions() != AIRPCAP_API_LOADED) {
		/*
		 * XXX - unless the error is "no such DLL", report this
		 * as an error rather than as "no AirPcap devices"?
		 */
		return (0);
	}

	if (!p_AirpcapGetDeviceList(&airpcap_devices, airpcap_errbuf)) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
		    "AirpcapGetDeviceList() failed: %s", airpcap_errbuf);
		return (-1);
	}

	for (airpcap_device = airpcap_devices; airpcap_device != NULL;
	    airpcap_device = airpcap_device->next) {
		if (pcapint_add_dev(devlistp, airpcap_device->Name, 0,
		    airpcap_device->Description, errbuf) == NULL) {
			/*
			 * Failure.
			 */
			p_AirpcapFreeDeviceList(airpcap_devices);
			return (-1);
		}
	}
	p_AirpcapFreeDeviceList(airpcap_devices);
	return (0);
}
