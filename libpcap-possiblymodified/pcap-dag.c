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
 * Author: Richard Littin, Sean Irvine ({richard,sean}@reeltwo.com)
 *
 * Modifications:
 *   2003 May - Jesper Peterson <support@endace.com>
 *              Code shuffled around to suit fad-xxx.c structure
 *              Added atexit() handler to stop DAG if application is too lazy
 *   2003 September - Koryn Grant <koryn@endace.com>
 *              Added support for nonblocking operation.
 *              Added support for processing more than a single packet in pcap_dispatch().
 *              Fixed bug in loss counter code.
 *              Improved portability of loss counter code (e.g. use UINT_MAX instead of 0xffff).
 *              Removed unused local variables.
 *              Added required headers (ctype.h, limits.h, unistd.h, netinet/in.h).
 *   2003 October - Koryn Grant <koryn@endace.com.>
 *              Changed semantics to match those of standard pcap on linux.
 *                - packets rejected by the filter are not counted.
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header$ (LBL)";
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

#include <dagnew.h>
#include <dagapi.h>

#define MIN_DAG_SNAPLEN		12
#define MAX_DAG_SNAPLEN		2040
#define ATM_SNAPLEN		48

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

static void delete_pcap_dag(pcap_t *p) {
  pcap_dag_node_t *curr = NULL, *prev = NULL;

  for (prev = NULL, curr = pcap_dags;
      curr != NULL && curr->p != p;
      prev = curr, curr = curr->next) {
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

static void dag_platform_close(pcap_t *p) {

#ifdef linux
  if (p != NULL && p->md.device != NULL) {
    if(dag_stop(p->fd) < 0)
      fprintf(stderr,"dag_stop %s: %s\n", p->md.device, strerror(errno));
    if(dag_close(p->fd) < 0)
      fprintf(stderr,"dag_close %s: %s\n", p->md.device, strerror(errno));
    
    free(p->md.device);
  }
#else
  if (p != NULL) {
    if(dag_stop(p->fd) < 0)
      fprintf(stderr,"dag_stop: %s\n", strerror(errno));
    if(dag_close(p->fd) < 0)
      fprintf(stderr,"dag_close: %s\n", strerror(errno));
  }
#endif
  delete_pcap_dag(p);
  /* Note: don't need to call close(p->fd) here as dag_close(p->fd) does this. */
}

static void atexit_handler(void) {
  while (pcap_dags != NULL) {
    if (pcap_dags->pid == getpid()) {
      dag_platform_close(pcap_dags->p);
    } else {
      delete_pcap_dag(pcap_dags->p);
    }
  }
}

static int new_pcap_dag(pcap_t *p) {
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
static int dag_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user) {
	unsigned int processed = 0;
	int flags = p->md.dag_offset_flags;
	unsigned int nonblocking = flags & DAGF_NONBLOCK;

	for (;;)
	{
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

			p->md.dag_mem_top = dag_offset(p->fd, &(p->md.dag_mem_bottom), flags);
			if ((p->md.dag_mem_top - p->md.dag_mem_bottom < dag_record_size) && nonblocking)
			{
				/* Pcap is configured to process only available packets, and there aren't any. */
				return 0;
			}
		}
  
		/* Process the packets. */
		while (p->md.dag_mem_top - p->md.dag_mem_bottom >= dag_record_size) {

			unsigned short packet_len = 0;
			int caplen = 0;
			struct pcap_pkthdr	pcap_header;

			dag_record_t *header = (dag_record_t *)(p->md.dag_mem_base + p->md.dag_mem_bottom);
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
 
			if (IS_BIGENDIAN())
			{
				rlen = header->rlen;
			}
			else
			{
				rlen = ntohs(header->rlen);
			}
			p->md.dag_mem_bottom += rlen;

			switch(header->type) {
			case TYPE_ATM:
				packet_len = ATM_SNAPLEN;
				caplen = ATM_SNAPLEN;
				dp += 4;
				break;

			case TYPE_ETH:
				if (IS_BIGENDIAN())
				{
					packet_len = header->wlen;
				}
				else
				{
					packet_len = ntohs(header->wlen);
				}
				packet_len -= (p->md.dag_fcs_bits >> 3);
				caplen = rlen - dag_record_size - 2;
				if (caplen > packet_len)
				{
					caplen = packet_len;
				}
				dp += 2;
				break;

			case TYPE_HDLC_POS:
				if (IS_BIGENDIAN())
				{
					packet_len = header->wlen;
				}
				else
				{
					packet_len = ntohs(header->wlen);
				}
				packet_len -= (p->md.dag_fcs_bits >> 3);
				caplen = rlen - dag_record_size;
				if (caplen > packet_len)
				{
					caplen = packet_len;
				}
				break;
			}
 
			if (caplen > p->snapshot)
				caplen = p->snapshot;

			/* Count lost packets. */
			if (header->lctr) {
				if (p->md.stat.ps_drop > (UINT_MAX - header->lctr)) {
					p->md.stat.ps_drop = UINT_MAX;
				} else {
					p->md.stat.ps_drop += header->lctr;
				}
			}

			/* Run the packet filter if there is one. */
			if ((p->fcode.bf_insns == NULL) || bpf_filter(p->fcode.bf_insns, dp, packet_len, caplen)) {

				/* convert between timestamp formats */
				register unsigned long long ts;
				
				if (IS_BIGENDIAN())
				{
					ts = SWAP_TS(header->ts);
				}
				else
				{
					ts = header->ts;
				}

				pcap_header.ts.tv_sec  = ts >> 32;
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

		if (nonblocking || processed)
		{
			return processed;
		}
	}
  
	return processed;
}

/*
 *  Get a handle for a live capture from the given DAG device.  Passing a NULL
 *  device will result in a failure.  The promisc flag is ignored because DAG
 *  cards are always promiscuous.  The to_ms parameter is also ignored as it is
 *  not supported in hardware.
 *  
 *  See also pcap(3).
 */
pcap_t *dag_open_live(const char *device, int snaplen, int promisc, int to_ms, char *ebuf) {
  char conf[30]; /* dag configure string */
  pcap_t *handle;
  char *s;
  int n;
  
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

  if (strstr(device, "/dev") == NULL) {
    char * newDev = (char *)malloc(strlen(device) + 6);
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

  /* setup device parameters */
  if((handle->fd = dag_open((char *)device)) < 0) {
    snprintf(ebuf, PCAP_ERRBUF_SIZE, "dag_open %s: %s", device, pcap_strerror(errno));
    goto fail;
  }

  /* set the card snap length to the specified snaplen parameter */
  if (snaplen == 0 || snaplen > MAX_DAG_SNAPLEN) {
    snaplen = MAX_DAG_SNAPLEN;
  } else if (snaplen < MIN_DAG_SNAPLEN) {
    snaplen = MIN_DAG_SNAPLEN;
  }
  /* snap len has to be a multiple of 4 */
  snprintf(conf, 30, "varlen slen=%d", (snaplen + 3) & ~3); 

  fprintf(stderr, "Configuring DAG with '%s'.\n", conf);
  if(dag_configure(handle->fd, conf) < 0) {
    snprintf(ebuf, PCAP_ERRBUF_SIZE,"dag_configure %s: %s\n", device, pcap_strerror(errno));
    goto fail;
  }
  
  if((handle->md.dag_mem_base = dag_mmap(handle->fd)) == MAP_FAILED) {
    snprintf(ebuf, PCAP_ERRBUF_SIZE,"dag_mmap %s: %s\n", device, pcap_strerror(errno));
    goto fail;
  }
  
  if(dag_start(handle->fd) < 0) {
    snprintf(ebuf, PCAP_ERRBUF_SIZE, "dag_start %s: %s\n", device, pcap_strerror(errno));
    goto fail;
  }

  /*
   * Important! You have to ensure bottom is properly
   * initialized to zero on startup, it won't give you
   * a compiler warning if you make this mistake!
   */
  handle->md.dag_mem_bottom = 0;
  handle->md.dag_mem_top = 0;

  /* TODO: query the card */
  handle->md.dag_fcs_bits = 32;
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
  /*handle->md.timeout	= to_ms; */

  if ((handle->linktype = dag_get_datalink(handle)) < 0) {
    snprintf(ebuf, PCAP_ERRBUF_SIZE, "dag_get_linktype %s: unknown linktype\n", device);
	goto fail;
  }
  
  handle->bufsize = 0;

  if (new_pcap_dag(handle) < 0) {
    snprintf(ebuf, PCAP_ERRBUF_SIZE, "new_pcap_dag %s: %s\n", device, pcap_strerror(errno));
	goto fail;
  }

  /*
   * "select()" and "poll()" don't (yet) work on DAG device descriptors.
   */
  handle->selectable_fd = -1;

#ifdef linux
  handle->md.device = (char *)device;
#else
  free((char *)device);
  device = NULL;
#endif

  handle->read_op = dag_read;
  handle->setfilter_op = dag_setfilter;
  handle->set_datalink_op = dag_set_datalink;
  handle->getnonblock_op = pcap_getnonblock_fd;
  handle->setnonblock_op = dag_setnonblock;
  handle->stats_op = dag_stats;
  handle->close_op = dag_platform_close;

  return handle;

fail:
  if (device != NULL) {
	free((char *)device);
  }
  if (handle != NULL) {
	free(handle);
  }

  return NULL;
}

static int dag_stats(pcap_t *p, struct pcap_stat *ps) {
  /* This needs to be filled out correctly.  Hopefully a dagapi call will
     provide all necessary information.
  */
  /*p->md.stat.ps_recv = 0;*/
  /*p->md.stat.ps_drop = 0;*/
  
  *ps = p->md.stat;
 
  return 0;
}

/*
 * Get from "/proc/dag" all interfaces listed there; if they're
 * already in the list of interfaces we have, that won't add another
 * instance, but if they're not, that'll add them.
 *
 * We don't bother getting any addresses for them.
 *
 * We also don't fail if we couldn't open "/proc/dag"; we just leave
 * the list of interfaces as is.
 */
int
dag_platform_finddevs(pcap_if_t **devlistp, char *errbuf)
{
  FILE *proc_dag_f;
  char linebuf[512];
  int linenum;
  unsigned char *p;
  char name[512];	/* XXX - pick a size */
  char *q;
  int ret = 0;

  /* Quick exit if /proc/dag not readable */
  proc_dag_f = fopen("/proc/dag", "r");
  if (proc_dag_f == NULL)
  {
    int i;
    char dev[16] = "dagx";

    for (i = '0'; ret == 0 && i <= '9'; i++) {
      dev[3] = i;
      if (pcap_add_if(devlistp, dev, 0, NULL, errbuf) == -1) {
        /*
         * Failure.
         */
        ret = -1;
      }
    }
          
    return (ret);
  }

  for (linenum = 1;
        fgets(linebuf, sizeof linebuf, proc_dag_f) != NULL; linenum++) {
    
    /*
     * Skip the first two lines - they're headers.
     */
    if (linenum <= 2)
      continue;

    p = &linebuf[0];

    if (*p == '\0' || *p == '\n' || *p != 'D')
      continue;  /* not a Dag line */

    /*
     * Get the interface name.
     */
    q = &name[0];
    while (*p != '\0' && *p != ':') {
      if (*p != ' ')
        *q++ = tolower(*p++);
      else
        p++;
    }
    *q = '\0';

    /*
     * Add an entry for this interface, with no addresses.
     */
    p[strlen(p) - 1] = '\0'; /* get rid of \n */
    if (pcap_add_if(devlistp, name, 0, strdup(p + 2), errbuf) == -1) {
      /*
       * Failure.
       */
      ret = -1;
      break;
    }
  }
  if (ret != -1) {
    /*
     * Well, we didn't fail for any other reason; did we
     * fail due to an error reading the file?
     */
    if (ferror(proc_dag_f)) {
      (void)snprintf(errbuf, PCAP_ERRBUF_SIZE,
          "Error reading /proc/dag: %s",
          pcap_strerror(errno));
      ret = -1;
    }
  }

  (void)fclose(proc_dag_f);
  return (ret);
}

/*
 * Installs the given bpf filter program in the given pcap structure.  There is
 * no attempt to store the filter in kernel memory as that is not supported
 * with DAG cards.
 */
static int dag_setfilter(pcap_t *p, struct bpf_program *fp) {
  if (!p)
    return -1;
  if (!fp) {
    strncpy(p->errbuf, "setfilter: No filter specified",
	    sizeof(p->errbuf));
    return -1;
  }

  /* Make our private copy of the filter */

  if (install_bpf_program(p, fp) < 0) {
    snprintf(p->errbuf, sizeof(p->errbuf),
	     "malloc: %s", pcap_strerror(errno));
    return -1;
  }

  p->md.use_bpf = 0;

  return (0);
}

static int
dag_set_datalink(pcap_t *p, int dlt)
{
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
  int linktype = -1;

  /* Check the type through a dagapi call.
  */
  switch(dag_linktype(p->fd)) {
  case TYPE_HDLC_POS: {
      dag_record_t *record;

      /* peek at the first available record to see if it is PPP */
      while ((p->md.dag_mem_top - p->md.dag_mem_bottom) < (dag_record_size + 4)) {
        p->md.dag_mem_top = dag_offset(p->fd, &(p->md.dag_mem_bottom), 0);
      }
      record = (dag_record_t *)(p->md.dag_mem_base + p->md.dag_mem_bottom);

      if ((ntohl(record->rec.pos.hdlc) & 0xffff0000) == 0xff030000) {
        linktype = DLT_PPP_SERIAL;
        fprintf(stderr, "Set DAG linktype to %d (DLT_PPP_SERIAL)\n", linktype);
      } else {
        linktype = DLT_CHDLC;
        fprintf(stderr, "Set DAG linktype to %d (DLT_CHDLC)\n", linktype);
      }
      break;
    }
  case TYPE_ETH:
    linktype = DLT_EN10MB;
    fprintf(stderr, "Set DAG linktype to %d (DLT_EN10MB)\n", linktype);
    break;
  case TYPE_ATM: 
    linktype = DLT_ATM_RFC1483;
    fprintf(stderr, "Set DAG linktype to %d (DLT_ATM_RFC1483)\n", linktype);
    break;
  case TYPE_LEGACY:
    linktype = DLT_NULL;
    fprintf(stderr, "Set DAG linktype to %d (DLT_NULL)\n", linktype);
    break;
  default:
    fprintf(stderr, "Unknown DAG linktype %d\n", dag_linktype(p->fd));
    break;
  }

  return linktype;
}
