/*
 * pcap-dag.c: Packet capture interface for Endace DAG card.
 *
 * The functionality of this code attempts to mimic that of pcap-linux as much
 * as possible.  This code is compiled in several different ways depending on
 * whether DAG_ONLY and HAVE_DAG_API are defined.  If HAVE_DAG_API is not
 * defined it should not get compiled in, otherwise if DAG_ONLY is defined then
 * the 'dag_' function calls are renamed to 'pcap_' equivalents.  If DAG_ONLY
 * is not defined then nothing is altered - the dag_ functions will be
 * called as required from their pcap-linux/bpf equivalents.
 *
 * Authors: Richard Littin, Sean Irvine ({richard,sean}@reeltwo.com)
 * Modifications: Jesper Peterson  <support@endace.com>
 *                Koryn Grant      <support@endace.com>
 *                Stephen Donnelly <support@endace.com>
 */

#ifndef lint
static const char rcsid[] _U_ =
	"@(#) $Header: /tcpdump/master/libpcap/pcap-dag.c,v 1.21.2.3 2005/07/10 22:09:34 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>			/* optionally get BSD define */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "pcap-int.h"

#include <ctype.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct mbuf;		/* Squelch compiler warnings on some platforms for */
struct rtentry;		/* declarations in <net/if.h> */
#include <net/if.h>

#include "dagnew.h"
#include "dagapi.h"

#define MIN_DAG_SNAPLEN		12
#define MAX_DAG_SNAPLEN		2040
#define ATM_CELL_SIZE		52
#define ATM_HDR_SIZE		4

/* SunATM pseudo header */
struct sunatm_hdr {
	unsigned char	flags;		/* destination and traffic type */
	unsigned char	vpi;		/* VPI */
	unsigned short	vci;		/* VCI */
};

typedef struct pcap_dag_node {
	struct pcap_dag_node *next;
	pcap_t *p;
	pid_t pid;
} pcap_dag_node_t;

static pcap_dag_node_t *pcap_dags = NULL;
static int atexit_handler_installed = 0;
static const unsigned short endian_test_word = 0x0100;

#define IS_BIGENDIAN() (*((unsigned char *)&endian_test_word))

/*
 * Swap byte ordering of unsigned long long timestamp on a big endian
 * machine.
 */
#define SWAP_TS(ull)  ((ull & 0xff00000000000000LL) >> 56) | \
                      ((ull & 0x00ff000000000000LL) >> 40) | \
                      ((ull & 0x0000ff0000000000LL) >> 24) | \
                      ((ull & 0x000000ff00000000LL) >> 8)  | \
                      ((ull & 0x00000000ff000000LL) << 8)  | \
                      ((ull & 0x0000000000ff0000LL) << 24) | \
                      ((ull & 0x000000000000ff00LL) << 40) | \
                      ((ull & 0x00000000000000ffLL) << 56)


#ifdef DAG_ONLY
/* This code is required when compiling for a DAG device only. */
#include "pcap-dag.h"

/* Replace dag function names with pcap equivalent. */
#define dag_open_live pcap_open_live
#define dag_platform_finddevs pcap_platform_finddevs
#endif /* DAG_ONLY */

static int dag_setfilter(pcap_t *p, struct bpf_program *fp);
static int dag_stats(pcap_t *p, struct pcap_stat *ps);
static int dag_set_datalink(pcap_t *p, int dlt);
static int dag_get_datalink(pcap_t *p);
static int dag_setnonblock(pcap_t *p, int nonblock, char *errbuf);

static void
delete_pcap_dag(pcap_t *p)
{
	pcap_dag_node_t *curr = NULL, *prev = NULL;

	for (prev = NULL, curr = pcap_dags; curr != NULL && curr->p != p; prev = curr, curr = curr->next) {
		/* empty */
	}

	if (curr != NULL && curr->p == p) {
		if (prev != NULL) {
			prev->next = curr->next;
		} else {
			pcap_dags = curr->next;
		}
	}
}

/*
 * Performs a graceful shutdown of the DAG card, frees dynamic memory held
 * in the pcap_t structure, and closes the file descriptor for the DAG card.
 */

static void
dag_platform_close(pcap_t *p)
{
	
	if (p != NULL) {
#ifdef HAVE_DAG_STREAMS_API
		if(dag_stop_stream(p->fd, p->md.dag_stream) < 0)
			fprintf(stderr,"dag_stop_stream: %s\n", strerror(errno));
		
		if(dag_detach_stream(p->fd, p->md.dag_stream) < 0)
			fprintf(stderr,"dag_detach_stream: %s\n", strerror(errno));
#else
		if(dag_stop(p->fd) < 0)
			fprintf(stderr,"dag_stop: %s\n", strerror(errno));
#endif /* HAVE_DAG_STREAMS_API */
		if(dag_close(p->fd) < 0)
			fprintf(stderr,"dag_close: %s\n", strerror(errno));
#ifdef linux		
		free(p->md.device);
#endif
	}
	delete_pcap_dag(p);
	/* Note: don't need to call close(p->fd) here as dag_close(p->fd) does this. */
}

static void
atexit_handler(void)
{
	while (pcap_dags != NULL) {
		if (pcap_dags->pid == getpid()) {
			dag_platform_close(pcap_dags->p);
		} else {
			delete_pcap_dag(pcap_dags->p);
		}
	}
}

static int
new_pcap_dag(pcap_t *p)
{
	pcap_dag_node_t *node = NULL;

	if ((node = malloc(sizeof(pcap_dag_node_t))) == NULL) {
		return -1;
	}

	if (!atexit_handler_installed) {
		atexit(atexit_handler);
		atexit_handler_installed = 1;
	}

	node->next = pcap_dags;
	node->p = p;
	node->pid = getpid();

	pcap_dags = node;

	return 0;
}

/*
 *  Read at most max_packets from the capture stream and call the callback
 *  for each of them. Returns the number of packets handled, -1 if an
 *  error occured, or -2 if we were told to break out of the loop.
 */
static int
dag_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	unsigned int processed = 0;
	int flags = p->md.dag_offset_flags;
	unsigned int nonblocking = flags & DAGF_NONBLOCK;

	/* Get the next bufferful of packets (if necessary). */
	while (p->md.dag_mem_top - p->md.dag_mem_bottom < dag_record_size) {
 
		/*
		 * Has "pcap_breakloop()" been called?
		 */
		if (p->break_loop) {
			/*
			 * Yes - clear the flag that indicates that
			 * it has, and return -2 to indicate that
			 * we were told to break out of the loop.
			 */
			p->break_loop = 0;
			return -2;
		}

#ifdef HAVE_DAG_STREAMS_API
		/* dag_advance_stream() will block (unless nonblock is called)
		 * until 64kB of data has accumulated.
		 * If to_ms is set, it will timeout before 64kB has accumulated.
		 * We wait for 64kB because processing a few packets at a time
		 * can cause problems at high packet rates (>200kpps) due
		 * to inefficiencies.
		 * This does mean if to_ms is not specified the capture may 'hang'
		 * for long periods if the data rate is extremely slow (<64kB/sec)
		 * If non-block is specified it will return immediately. The user
		 * is then responsible for efficiency.
		 */
		p->md.dag_mem_top = dag_advance_stream(p->fd, p->md.dag_stream, (void**)&(p->md.dag_mem_bottom));
#else
		/* dag_offset does not support timeouts */
		p->md.dag_mem_top = dag_offset(p->fd, &(p->md.dag_mem_bottom), flags);
#endif /* HAVE_DAG_STREAMS_API */

		if (nonblocking && (p->md.dag_mem_top - p->md.dag_mem_bottom < dag_record_size))
		{
			/* Pcap is configured to process only available packets, and there aren't any, return immediately. */
			return 0;
		}
		
		if(!nonblocking &&
		   p->md.dag_timeout &&
		   (p->md.dag_mem_top - p->md.dag_mem_bottom < dag_record_size))
		{
			/* Blocking mode, but timeout set and no data has arrived, return anyway.*/
			return 0;
		}

	}
	
	/* Process the packets. */
	while (p->md.dag_mem_top - p->md.dag_mem_bottom >= dag_record_size) {

		unsigned short packet_len = 0;
		int caplen = 0;
		struct pcap_pkthdr	pcap_header;

#ifdef HAVE_DAG_STREAMS_API
		dag_record_t *header = (dag_record_t *)(p->md.dag_mem_bottom);
#else
		dag_record_t *header = (dag_record_t *)(p->md.dag_mem_base + p->md.dag_mem_bottom);
#endif /* HAVE_DAG_STREAMS_API */

		u_char *dp = ((u_char *)header) + dag_record_size;
		unsigned short rlen;
 
		/*
		 * Has "pcap_breakloop()" been called?
		 */
		if (p->break_loop) {
			/*
			 * Yes - clear the flag that indicates that
			 * it has, and return -2 to indicate that
			 * we were told to break out of the loop.
			 */
			p->break_loop = 0;
			return -2;
		}
 
		rlen = ntohs(header->rlen);
		if (rlen < dag_record_size)
		{
			strncpy(p->errbuf, "dag_read: record too small", PCAP_ERRBUF_SIZE);
			return -1;
		}
		p->md.dag_mem_bottom += rlen;

		switch(header->type) {
		case TYPE_AAL5:
		case TYPE_ATM:
#ifdef TYPE_MC_ATM
		case TYPE_MC_ATM:
			if (header->type == TYPE_MC_ATM) {
				caplen = packet_len = ATM_CELL_SIZE;
				dp+=4;
			}
#endif
#ifdef TYPE_MC_AAL5
		case TYPE_MC_AAL5:
			if (header->type == TYPE_MC_AAL5) {
				packet_len = ntohs(header->wlen);
				caplen = rlen - dag_record_size - 4;
				dp+=4;
			}
#endif
			if (header->type == TYPE_AAL5) {
				packet_len = ntohs(header->wlen);
				caplen = rlen - dag_record_size;
			} else if(header->type == TYPE_ATM) {
				caplen = packet_len = ATM_CELL_SIZE;
			}
			if (p->linktype == DLT_SUNATM) {
				struct sunatm_hdr *sunatm = (struct sunatm_hdr *)dp;
				unsigned long rawatm;
					
				rawatm = ntohl(*((unsigned long *)dp));
				sunatm->vci = htons((rawatm >>  4) & 0xffff);
				sunatm->vpi = (rawatm >> 20) & 0x00ff;
				sunatm->flags = ((header->flags.iface & 1) ? 0x80 : 0x00) | 
					((sunatm->vpi == 0 && sunatm->vci == htons(5)) ? 6 :
					 ((sunatm->vpi == 0 && sunatm->vci == htons(16)) ? 5 : 
					  ((dp[ATM_HDR_SIZE] == 0xaa &&
					    dp[ATM_HDR_SIZE+1] == 0xaa &&
					    dp[ATM_HDR_SIZE+2] == 0x03) ? 2 : 1)));

			} else {
				packet_len -= ATM_HDR_SIZE;
				caplen -= ATM_HDR_SIZE;
				dp += ATM_HDR_SIZE;
			}
			break;

#ifdef TYPE_COLOR_ETH
		case TYPE_COLOR_ETH:
#endif
		case TYPE_ETH:
			packet_len = ntohs(header->wlen);
			packet_len -= (p->md.dag_fcs_bits >> 3);
			caplen = rlen - dag_record_size - 2;
			if (caplen > packet_len) {
				caplen = packet_len;
			}
			dp += 2;
			break;
#ifdef TYPE_COLOR_HDLC_POS
		case TYPE_COLOR_HDLC_POS:
#endif
		case TYPE_HDLC_POS:
			packet_len = ntohs(header->wlen);
			packet_len -= (p->md.dag_fcs_bits >> 3);
			caplen = rlen - dag_record_size;
			if (caplen > packet_len) {
				caplen = packet_len;
			}
			break;
#ifdef TYPE_MC_HDLC
		case TYPE_MC_HDLC:
			packet_len = ntohs(header->wlen);
			packet_len -= (p->md.dag_fcs_bits >> 3);
			caplen = rlen - dag_record_size - 4;
			if (caplen > packet_len) {
				caplen = packet_len;
			}
			dp += 4;
			break;
#endif
		}
 
		if (caplen > p->snapshot)
			caplen = p->snapshot;

		/* Count lost packets. */
		switch(header->type) {
#ifdef TYPE_COLOR_HDLC_POS
			/* in this type the color value overwrites the lctr */
		case TYPE_COLOR_HDLC_POS:
			break;
#endif
#ifdef TYPE_COLOR_ETH
			/* in this type the color value overwrites the lctr */
		case TYPE_COLOR_ETH:
			break;
#endif
		default:
			if (header->lctr) {
				if (p->md.stat.ps_drop > (UINT_MAX - ntohs(header->lctr))) {
					p->md.stat.ps_drop = UINT_MAX;
				} else {
					p->md.stat.ps_drop += ntohs(header->lctr);
				}
			}
		}

		/* Run the packet filter if there is one. */
		if ((p->fcode.bf_insns == NULL) || bpf_filter(p->fcode.bf_insns, dp, packet_len, caplen)) {

			/* convert between timestamp formats */
			register unsigned long long ts;
				
			if (IS_BIGENDIAN()) {
				ts = SWAP_TS(header->ts);
			} else {
				ts = header->ts;
			}

			pcap_header.ts.tv_sec = ts >> 32;
			ts = (ts & 0xffffffffULL) * 1000000;
			ts += 0x80000000; /* rounding */
			pcap_header.ts.tv_usec = ts >> 32;		
			if (pcap_header.ts.tv_usec >= 1000000) {
				pcap_header.ts.tv_usec -= 1000000;
				pcap_header.ts.tv_sec++;
			}

			/* Fill in our own header data */
			pcap_header.caplen = caplen;
			pcap_header.len = packet_len;
	
			/* Count the packet. */
			p->md.stat.ps_recv++;
	
			/* Call the user supplied callback function */
			callback(user, &pcap_header, dp);
	
			/* Only count packets that pass the filter, for consistency with standard Linux behaviour. */
			processed++;
			if (processed == cnt)
			{
				/* Reached the user-specified limit. */
				return cnt;
			}
		}
	}

	return processed;
}

static int
dag_inject(pcap_t *p, const void *buf _U_, size_t size _U_)
{
	strlcpy(p->errbuf, "Sending packets isn't supported on DAG cards",
	    PCAP_ERRBUF_SIZE);
	return (-1);
}

/*
 *  Get a handle for a live capture from the given DAG device.  Passing a NULL
 *  device will result in a failure.  The promisc flag is ignored because DAG
 *  cards are always promiscuous.  The to_ms parameter is also ignored as it is
 *  not supported in hardware.
 *  
 *  See also pcap(3).
 */
pcap_t *
dag_open_live(const char *device, int snaplen, int promisc, int to_ms, char *ebuf)
{
	char conf[30]; /* dag configure string */
	pcap_t *handle;
	char *s;
	int n;
	daginf_t* daginf;
	char * newDev;
#ifdef HAVE_DAG_STREAMS_API
	uint32_t mindata;
	struct timeval maxwait;
	struct timeval poll;
#endif

	if (device == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "device is NULL: %s", pcap_strerror(errno));
		return NULL;
	}
	/* Allocate a handle for this session. */

	handle = malloc(sizeof(*handle));
	if (handle == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc %s: %s", device, pcap_strerror(errno));
		return NULL;
	}
	
	/* Initialize some components of the pcap structure. */
	
	memset(handle, 0, sizeof(*handle));

	newDev = (char *)malloc(strlen(device) + 16);

#ifdef HAVE_DAG_STREAMS_API
	
	/* Parse input name to get dag device and stream number if provided */
	if (dag_parse_name(device, newDev, strlen(device) + 16, &handle->md.dag_stream) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "dag_parse_name: %s\n", pcap_strerror(errno));
		goto fail;
	}
	device = newDev;

	if (handle->md.dag_stream%2) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "dag_parse_name: tx (even numbered) streams not supported for capture\n");
		goto fail;
	}
#else
	if (strstr(device, "/dev") == NULL) {
		newDev[0] = '\0';
		strcat(newDev, "/dev/");
		strcat(newDev,device);
		device = newDev;
	} else {
		device = strdup(device);
	}

	if (device == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "str_dup: %s\n", pcap_strerror(errno));
		goto fail;
	}
#endif /* HAVE_DAG_STREAMS_API */

	/* setup device parameters */
	if((handle->fd = dag_open((char *)device)) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "dag_open %s: %s", device, pcap_strerror(errno));
		goto fail;
	}

#ifdef HAVE_DAG_STREAMS_API
	/* Open requested stream. Can fail if already locked or on error */
	if (dag_attach_stream(handle->fd, handle->md.dag_stream, 0, 0) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "dag_attach_stream: %s\n", pcap_strerror(errno));
		goto fail;
	}

	/* Set up default poll parameters for stream
	 * Can be overridden by pcap_set_nonblock()
	 */
	if (dag_get_stream_poll(handle->fd, handle->md.dag_stream,
				&mindata, &maxwait, &poll) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "dag_get_stream_poll: %s\n", pcap_strerror(errno));
		goto fail;
	}
	
	/* Amount of data to collect in Bytes before calling callbacks.
	 * Important for efficiency, but can introduce latency
	 * at low packet rates if to_ms not set!
	 */
	mindata = 65536;

	/* Obey to_ms if supplied. This is a good idea!
	 * Recommend 10-100ms. Calls will time out even if no data arrived.
	 */
	maxwait.tv_sec = to_ms/1000;
	maxwait.tv_usec = (to_ms%1000) * 1000;

	if (dag_set_stream_poll(handle->fd, handle->md.dag_stream,
				mindata, &maxwait, &poll) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "dag_set_stream_poll: %s\n", pcap_strerror(errno));
		goto fail;
	}
		
#else
	if((handle->md.dag_mem_base = dag_mmap(handle->fd)) == MAP_FAILED) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,"dag_mmap %s: %s\n", device, pcap_strerror(errno));
		goto fail;
	}

#endif /* HAVE_DAG_STREAMS_API */

	/* set the card snap length to the specified snaplen parameter */
	if (snaplen == 0 || snaplen > MAX_DAG_SNAPLEN) {
		snaplen = MAX_DAG_SNAPLEN;
	} else if (snaplen < MIN_DAG_SNAPLEN) {
		snaplen = MIN_DAG_SNAPLEN;
	}
	/* snap len has to be a multiple of 4 */
	snprintf(conf, 30, "varlen slen=%d", (snaplen + 3) & ~3); 

	if(dag_configure(handle->fd, conf) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE,"dag_configure %s: %s\n", device, pcap_strerror(errno));
		goto fail;
	}
		
#ifdef HAVE_DAG_STREAMS_API
	if(dag_start_stream(handle->fd, handle->md.dag_stream) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "dag_start_stream %s: %s\n", device, pcap_strerror(errno));
		goto fail;
	}
#else
	if(dag_start(handle->fd) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "dag_start %s: %s\n", device, pcap_strerror(errno));
		goto fail;
	}
#endif /* HAVE_DAG_STREAMS_API */

	/*
	 * Important! You have to ensure bottom is properly
	 * initialized to zero on startup, it won't give you
	 * a compiler warning if you make this mistake!
	 */
	handle->md.dag_mem_bottom = 0;
	handle->md.dag_mem_top = 0;
	handle->md.dag_fcs_bits = 32;

	/* Query the card first for special cases. */
	daginf = dag_info(handle->fd);
	if ((0x4200 == daginf->device_code) || (0x4230 == daginf->device_code))
	{
		/* DAG 4.2S and 4.23S already strip the FCS.  Stripping the final word again truncates the packet. */
		handle->md.dag_fcs_bits = 0;
	}

	/* Then allow an environment variable to override. */
	if ((s = getenv("ERF_FCS_BITS")) != NULL) {
		if ((n = atoi(s)) == 0 || n == 16|| n == 32) {
			handle->md.dag_fcs_bits = n;
		} else {
			snprintf(ebuf, PCAP_ERRBUF_SIZE,
				"pcap_open_live %s: bad ERF_FCS_BITS value (%d) in environment\n", device, n);
			goto fail;
		}
	}

	handle->snapshot	= snaplen;
	handle->md.dag_timeout	= to_ms;

	handle->linktype = -1;
	if (dag_get_datalink(handle) < 0) {
		strcpy(ebuf, handle->errbuf);
		goto fail;
	}
	
	handle->bufsize = 0;

	if (new_pcap_dag(handle) < 0) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "new_pcap_dag %s: %s\n", device, pcap_strerror(errno));
		goto fail;
	}

	/*
	 * "select()" and "poll()" don't work on DAG device descriptors.
	 */
	handle->selectable_fd = -1;

#ifdef linux
	handle->md.device = (char *)device;
	handle->md.timeout = to_ms;
#else
	free((char *)device);
	device = NULL;
#endif

	handle->read_op = dag_read;
	handle->inject_op = dag_inject;
	handle->setfilter_op = dag_setfilter;
	handle->setdirection_op = NULL; /* Not implemented.*/
	handle->set_datalink_op = dag_set_datalink;
	handle->getnonblock_op = pcap_getnonblock_fd;
	handle->setnonblock_op = dag_setnonblock;
	handle->stats_op = dag_stats;
	handle->close_op = dag_platform_close;

	return handle;

fail:
	if (newDev != NULL) {
		free((char *)newDev);
	}
	if (handle != NULL) {
		/*
		 * Get rid of any link-layer type list we allocated.
		 */
		if (handle->dlt_list != NULL) {
			free(handle->dlt_list);
		}
		free(handle);
	}

	return NULL;
}

static int
dag_stats(pcap_t *p, struct pcap_stat *ps) {
	/* This needs to be filled out correctly.  Hopefully a dagapi call will
		 provide all necessary information.
	*/
	/*p->md.stat.ps_recv = 0;*/
	/*p->md.stat.ps_drop = 0;*/
	
	*ps = p->md.stat;
 
	return 0;
}

/*
 * Simply submit all possible dag names as candidates.
 * pcap_add_if() internally tests each candidate with pcap_open_live(),
 * so any non-existent devices are dropped.
 * For 2.5 try all rx stream names as well.
 */
int
dag_platform_finddevs(pcap_if_t **devlistp, char *errbuf)
{
	char name[12];	/* XXX - pick a size */
	int ret = 0;
	int c;

	/* Try all the DAGs 0-9 */
	for (c = 0; c < 9; c++) {
		snprintf(name, 12, "dag%d", c);
		if (pcap_add_if(devlistp, name, 0, NULL, errbuf) == -1) {
			/*
			 * Failure.
			 */
			ret = -1;
		}
#ifdef HAVE_DAG_STREAMS_API
		{
			int stream;
			for(stream=0;stream<16;stream+=2) {
				snprintf(name,  10, "dag%d:%d", c, stream);
				if (pcap_add_if(devlistp, name, 0, NULL, errbuf) == -1) {
					/*
					 * Failure.
					 */
					ret = -1;
				}
			}				
		}
#endif  /* HAVE_DAG_STREAMS_API */
	}
	return (ret);
}

/*
 * Installs the given bpf filter program in the given pcap structure.  There is
 * no attempt to store the filter in kernel memory as that is not supported
 * with DAG cards.
 */
static int
dag_setfilter(pcap_t *p, struct bpf_program *fp)
{
	if (!p)
		return -1;
	if (!fp) {
		strncpy(p->errbuf, "setfilter: No filter specified",
			sizeof(p->errbuf));
		return -1;
	}

	/* Make our private copy of the filter */

	if (install_bpf_program(p, fp) < 0)
		return -1;

	p->md.use_bpf = 0;

	return (0);
}

static int
dag_set_datalink(pcap_t *p, int dlt)
{
	p->linktype = dlt;

	return (0);
}

static int
dag_setnonblock(pcap_t *p, int nonblock, char *errbuf)
{
	/*
	 * Set non-blocking mode on the FD.
	 * XXX - is that necessary?  If not, don't bother calling it,
	 * and have a "dag_getnonblock()" function that looks at
	 * "p->md.dag_offset_flags".
	 */
	if (pcap_setnonblock_fd(p, nonblock, errbuf) < 0)
		return (-1);
#ifdef HAVE_DAG_STREAMS_API
	{
		uint32_t mindata;
		struct timeval maxwait;
		struct timeval poll;
		
		if (dag_get_stream_poll(p->fd, p->md.dag_stream,
					&mindata, &maxwait, &poll) < 0) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE, "dag_get_stream_poll: %s\n", pcap_strerror(errno));
			return -1;
		}
		
		/* Amount of data to collect in Bytes before calling callbacks.
		 * Important for efficiency, but can introduce latency
		 * at low packet rates if to_ms not set!
		 */
		if(nonblock)
			mindata = 0;
		else
			mindata = 65536;
		
		if (dag_set_stream_poll(p->fd, p->md.dag_stream,
					mindata, &maxwait, &poll) < 0) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE, "dag_set_stream_poll: %s\n", pcap_strerror(errno));
			return -1;
		}
	}
#endif /* HAVE_DAG_STREAMS_API */
	if (nonblock) {
		p->md.dag_offset_flags |= DAGF_NONBLOCK;
	} else {
		p->md.dag_offset_flags &= ~DAGF_NONBLOCK;
	}
	return (0);
}
		
static int
dag_get_datalink(pcap_t *p)
{
	int daglinktype;

	if (p->dlt_list == NULL && (p->dlt_list = malloc(2*sizeof(*(p->dlt_list)))) == NULL) {
		(void)snprintf(p->errbuf, sizeof(p->errbuf), "malloc: %s", pcap_strerror(errno));
		return (-1);
	}

	/* Check the type through a dagapi call. */
	daglinktype = dag_linktype(p->fd);

	switch(daglinktype) {

	case TYPE_HDLC_POS:
	case TYPE_COLOR_HDLC_POS:
		if (p->dlt_list != NULL) {
			p->dlt_count = 2;
			p->dlt_list[0] = DLT_CHDLC;
			p->dlt_list[1] = DLT_PPP_SERIAL;
			p->dlt_list[2] = DLT_FRELAY;
		}
		p->linktype = DLT_CHDLC;
		break;

	case TYPE_ETH:
	case TYPE_COLOR_ETH:
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
		if (p->dlt_list != NULL) {
			p->dlt_count = 2;
			p->dlt_list[0] = DLT_EN10MB;
			p->dlt_list[1] = DLT_DOCSIS;
		}
		p->linktype = DLT_EN10MB;
		break;

	case TYPE_AAL5:
	case TYPE_ATM: 
	case TYPE_MC_ATM:
	case TYPE_MC_AAL5:
		if (p->dlt_list != NULL) {
			p->dlt_count = 2;
			p->dlt_list[0] = DLT_ATM_RFC1483;
			p->dlt_list[1] = DLT_SUNATM;
		}
		p->linktype = DLT_ATM_RFC1483;
		break;

	case TYPE_MC_HDLC:
		if (p->dlt_list != NULL) {
			p->dlt_count = 4;
			p->dlt_list[0] = DLT_CHDLC;
			p->dlt_list[1] = DLT_PPP_SERIAL;
			p->dlt_list[2] = DLT_FRELAY;
			p->dlt_list[3] = DLT_MTP2;
		}
		p->linktype = DLT_CHDLC;
		break;

	case TYPE_LEGACY:
		p->linktype = DLT_NULL;
		break;

	default:
		snprintf(p->errbuf, sizeof(p->errbuf), "unknown DAG linktype %d\n", daglinktype);
		return (-1);

	}

	return p->linktype;
}
