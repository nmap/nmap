#ifndef NSOCK_PCAP_H 
#define NSOCK_PCAP_H

#include "nsock_internal.h"
#ifdef HAVE_PCAP

#include "pcap.h"

#include <string.h>
#include <stdarg.h>


/*
 * There are three possible ways of reading packets from pcap descriptor:
 *  do select() on descriptor -> this one is of course the best, but 
 *              there are systems that don't support this like WIN32
 * 		This works perfectly for Linux.
 *  do select() but whith some hacks -> this one is hack for older bsd
 * 		systems, Descriptor *must* be set in nonblocking mode.
 *  never do select() -> this one is for WIN32 and other systems that
 * 		return descriptor -1 from pcap_get_selectable_fd()
 * 		In this case descriptor *must* be set in nonblocking mode.
 * 		If that fails than we can't do any sniffing from that box.
 * 
 * In all cases we try to set descriptor to non-blocking mode.
 * */

// Returns whether the system supports pcap_get_selectable_fd() properly
#if !defined(WIN32) && !defined(SOLARIS)
#define PCAP_CAN_DO_SELECT 1
#endif

/*
 * In some systems (like Windows), the pcap descriptor is not selectable. Therefore,
 * we cannot just select() on it and expect it to wake us up and deliver a packet,
 * but we need to poll it continuously. This define sets the frequency, in milliseconds,
 * at which the pcap handle is polled to determine if there are any captured packets.
 * Note that this is only used when PCAP_CAN_DO_SELECT is not defined and therefore it
 * has no effect on systems like Linux.
 */
#define PCAP_POLL_INTERVAL 2

/*
 * Note that on most versions of most BSDs (including Mac OS X) select() and poll() do not work 
 * correctly on BPF devices; pcap_get_selectable_fd() will return a file descriptor on most of those 
 * versions (the exceptions being FreeBSD 4.3 and 4.4), a simple select() or poll() will 
 * not return even after a timeout specified in pcap_open_live() expires. To work around 
 * this, an application that uses select() or poll() to wait for packets to arrive must put 
 * the pcap_t in non-blocking mode, and must arrange that the select() or poll() have a timeout 
 * less than or equal to the timeout specified in pcap_open_live(), and must try to read packets 
 * after that timeout expires, regardless of whether select() or poll() indicated that the file 
 * descriptor for the pcap_t is ready to be read or not. (That workaround will not work in 
 * FreeBSD 4.3 and later; however, in FreeBSD 4.6 and later, select() and poll() work correctly 
 * on BPF devices, so the workaround isn't necessary, although it does no harm.)
 */
#if defined(MACOSX) || defined(FREEBSD) || defined(OPENBSD)
// Well, now select() is not receiving any pcap events on MACOSX, but maybe it will someday :)
// in both cases. It never hurts to enable this feature. It just has performance penalty.  
#define PCAP_BSD_SELECT_HACK 1
#endif

// Returns whether the packet receive time value obtained from libpcap
// (and thus by readip_pcap()) should be considered valid.  When
// invalid (Windows and Amiga), readip_pcap returns the time you called it.
#if !defined(WIN32) && !defined(__amigaos__)
#define PCAP_RECV_TIMEVAL_VALID 1 
#endif


typedef struct{
	pcap_t *pt;
	int pcap_desc;
	/* Like the corresponding member in msiod, when this reaches 0 we stop
	   watching the socket for readability. */
	int readsd_count;
	int datalink;
	int l3_offset;
	int snaplen;
	char *pcap_device;
} mspcap;


typedef struct{
	struct timeval ts;
	int caplen;
	int len;
	const unsigned char *packet;	// caplen bytes
} nsock_pcap;

int do_actual_pcap_read(msevent *nse);

#endif /* HAVE_PCAP */
#endif /* NSOCK_PCAP_H */
