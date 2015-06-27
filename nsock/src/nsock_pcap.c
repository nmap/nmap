/***************************************************************************
 * nsock_pcap.c -- This contains pcap operations functions from            *
 * the nsock parallel socket event library                                 *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2015 Insecure.Com   *
 * LLC This library is free software; you may redistribute and/or          *
 * modify it under the terms of the GNU General Public License as          *
 * published by the Free Software Foundation; Version 2.  This guarantees  *
 * your right to use, modify, and redistribute this software under certain *
 * conditions.  If this license is unacceptable to you, Insecure.Com LLC   *
 * may be willing to sell alternative licenses (contact                    *
 * sales@insecure.com ).                                                   *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement stating    *
 * terms other than the (GPL) terms above, then that alternative license   *
 * agreement takes precedence over this comment.                           *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details                            *
 * (http://www.gnu.org/licenses/gpl-2.0.html).                             *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "nsock.h"
#include "nsock_internal.h"
#include "nsock_log.h"

#include <limits.h>
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#if HAVE_NET_BPF_H
#ifdef _AIX
/* Prevent bpf.h from redefining the DLT_ values to their IFT_ values. (See
 * similar comment in libpcap/pcap-bpf.c.) */
#undef _AIX
#include <net/bpf.h>
#define _AIX
#else
#include <net/bpf.h>
#endif
#endif

#include "nsock_pcap.h"

extern struct timeval nsock_tod;

#if HAVE_PCAP

#define PCAP_OPEN_MAX_RETRIES   3

#define PCAP_FAILURE_EXPL_MESSAGE  \
    "There are several possible reasons for this, " \
    "depending on your operating system:\n" \
    "LINUX: If you are getting Socket type not supported, " \
    "try modprobe af_packet or recompile your kernel with PACKET enabled.\n" \
    "*BSD:  If you are getting device not configured, you need to recompile " \
    "your kernel with Berkeley Packet Filter support." \
    "If you are getting No such file or directory, try creating the device " \
    "(eg cd /dev; MAKEDEV <device>; or use mknod).\n" \
    "*WINDOWS:  Nmap only supports ethernet interfaces on Windows for most " \
    "operations because Microsoft disabled raw sockets as of Windows XP SP2. " \
    "Depending on the reason for this error, it is possible that the " \
    "--unprivileged command-line argument will help.\n" \
    "SOLARIS:  If you are trying to scan localhost and getting "\
    "'/dev/lo0: No such file or directory', complain to Sun.  "\
    "I don't think Solaris can support advanced localhost scans.  "\
    "You can probably use \"-PN -sT localhost\" though.\n\n"


static int nsock_pcap_set_filter(struct npool *nsp, pcap_t *pt, const char *device,
                                 const char *bpf) {
  struct bpf_program fcode;
  int rc;

  rc = pcap_compile(pt, &fcode, (char *)bpf, 1, PCAP_NETMASK_UNKNOWN);
  if (rc) {
    nsock_log_error("Error compiling pcap filter: %s", pcap_geterr(pt));
    return rc;
  }

  rc = pcap_setfilter(pt, &fcode);
  if (rc) {
    nsock_log_error("Failed to set the pcap filter: %s", pcap_geterr(pt));
    return rc;
  }

  pcap_freecode(&fcode);
  return 0;
}

static int nsock_pcap_get_l3_offset(pcap_t *pt, int *dl) {
  int datalink;
  unsigned int offset = 0;

  /* New packet capture device, need to recompute offset */
  if ((datalink = pcap_datalink(pt)) < 0)
    fatal("Cannot obtain datalink information: %s", pcap_geterr(pt));

  /* XXX NOTE:
   * if a new offset ever exceeds the current max (24),
   * adjust MAX_LINK_HEADERSZ in libnetutil/netutil.h
   */
  switch (datalink) {
    case DLT_EN10MB: offset = 14; break;
    case DLT_IEEE802: offset = 22; break;
    #ifdef __amigaos__
    case DLT_MIAMI: offset = 16; break;
    #endif
    #ifdef DLT_LOOP
    case DLT_LOOP:
    #endif
    case DLT_NULL: offset = 4; break;

    case DLT_SLIP:
    #ifdef DLT_SLIP_BSDOS
    case DLT_SLIP_BSDOS:
    #endif
    #if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
    offset = 16;break;
    #else
    offset = 24;break; /* Anyone use this??? */
    #endif

    case DLT_PPP:
    #ifdef DLT_PPP_BSDOS
    case DLT_PPP_BSDOS:
    #endif
    #ifdef DLT_PPP_SERIAL
    case DLT_PPP_SERIAL:
    #endif
    #ifdef DLT_PPP_ETHER
    case DLT_PPP_ETHER:
    #endif
    #if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
    offset = 4;break;
    #else
      #ifdef SOLARIS
        offset = 8;break;
      #else
        offset = 24;break; /* Anyone use this? */
      #endif /* ifdef solaris */
    #endif /* if freebsd || openbsd || netbsd || bsdi */
    #ifdef DLT_RAW
    case DLT_RAW: offset = 0; break;
    #endif /* DLT_RAW */
    case DLT_FDDI: offset = 21; break;
    #ifdef DLT_ENC
    case DLT_ENC: offset = 12; break;
    #endif /* DLT_ENC */
    #ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL: offset = 16; break;
    #endif
    #ifdef DLT_IPNET
    case DLT_IPNET: offset = 24; break;
    #endif /* DLT_IPNET */

    default: /* Sorry, link type is unknown. */
      fatal("Unknown datalink type %d.\n", datalink);
  }
  if (dl)
    *dl = datalink;
  return (offset);
}

static int nsock_pcap_try_open(struct npool *nsp, mspcap *mp, const char *dev,
                               int snaplen, int promisc, int timeout_ms,
                               char *errbuf) {
    mp->pt = pcap_open_live(dev, snaplen, promisc, timeout_ms, errbuf);
    if (!mp->pt) {
      nsock_log_error("pcap_open_live(%s, %d, %d, %d) failed with error: %s",
                      dev, snaplen, promisc, timeout_ms, errbuf);
      return -1;
    }
    return 0;
}

/* Convert new nsiod to pcap descriptor. Other parameters have
 * the same meaning as for pcap_open_live in pcap(3).
 *   device   : pcap-style device name
 *   snaplen  : size of packet to be copied to handler
 *   promisc  : whether to open device in promiscuous mode
 *   bpf_fmt   : berkeley filter
 * return value: NULL if everything was okay, or error string
 * if error occurred. */
int nsock_pcap_open(nsock_pool nsp, nsock_iod nsiod, const char *pcap_device,
                    int snaplen, int promisc, const char *bpf_fmt, ...) {
  struct niod *nsi = (struct niod *)nsiod;
  struct npool *ms = (struct npool *)nsp;
  mspcap *mp = (mspcap *)nsi->pcap;
  char errbuf[PCAP_ERRBUF_SIZE];
  char bpf[4096];
  va_list ap;
  int failed, datalink;
  int rc;

#ifdef PCAP_CAN_DO_SELECT
#if PCAP_BSD_SELECT_HACK
  /* MacOsX reports error if to_ms is too big (like INT_MAX) with error
   * FAILED. Reported error: BIOCSRTIMEOUT: Invalid argument
   * INT_MAX/6 (=357913941) seems to be working... */
  int to_ms = 357913941;
#else
  int to_ms = 200;
#endif /* PCAP_BSD_SELECT_HACK */

#else
  int to_ms = 1;
#endif

  gettimeofday(&nsock_tod, NULL);

  if (mp) {
    nsock_log_error("This nsi already has pcap device opened");
    return -1;
  }

  mp = (mspcap *)safe_zalloc(sizeof(mspcap));
  nsi->pcap = (void *)mp;

  va_start(ap, bpf_fmt);
  rc = Vsnprintf(bpf, sizeof(bpf), bpf_fmt, ap);
  va_end(ap);

  if (rc >= (int)sizeof(bpf)) {
    nsock_log_error("Too-large bpf filter argument");
    return -1;
  }

  nsock_log_info("PCAP requested on device '%s' with berkeley filter '%s' "
                 "(promisc=%i snaplen=%i to_ms=%i) (IOD #%li)",
                 pcap_device,bpf, promisc, snaplen, to_ms, nsi->id);

  failed = 0;
  do {
    rc = nsock_pcap_try_open(ms, mp, pcap_device, snaplen, promisc, to_ms, errbuf);
    if (rc) {
      failed++;
      nsock_log_error("Will wait %d seconds then retry.", 4 * failed);
      sleep(4 * failed);
    }
  } while (rc && failed < PCAP_OPEN_MAX_RETRIES);

  if (rc) {
    nsock_log_error("pcap_open_live(%s, %d, %d, %d) failed %d times.",
                    pcap_device, snaplen, promisc, to_ms, failed);
    nsock_log_error(PCAP_FAILURE_EXPL_MESSAGE);
    nsock_log_error("Can't open pcap! Are you root?");
    return -1;
  }

  rc = nsock_pcap_set_filter(ms, mp->pt, pcap_device, bpf);
  if (rc)
    return rc;

#ifdef WIN32
  /* We want any responses back ASAP */
  pcap_setmintocopy(mp->pt, 1);
#endif

  mp->l3_offset = nsock_pcap_get_l3_offset(mp->pt, &datalink);
  mp->snaplen = snaplen;
  mp->datalink = datalink;
  mp->pcap_device = strdup(pcap_device);
#ifdef PCAP_CAN_DO_SELECT
  mp->pcap_desc = pcap_get_selectable_fd(mp->pt);
#else
  mp->pcap_desc = -1;
#endif
  mp->readsd_count = 0;

  /* Without setting this ioctl, some systems (BSDs, though it depends on the
   * release) will buffer packets in non-blocking mode and only return them in a
   * bunch when the buffer is full. Setting the ioctl makes each one be
   * delivered immediately. This is how Linux works by default. See the comments
   * surrounding the setting of BIOCIMMEDIATE in libpcap/pcap-bpf.c. */
#ifdef BIOCIMMEDIATE
  if (mp->pcap_desc != -1) {
    int immediate = 1;

    if (ioctl(mp->pcap_desc, BIOCIMMEDIATE, &immediate) < 0)
      fatal("Cannot set BIOCIMMEDIATE on pcap descriptor");
  }
#endif

  /* Set device non-blocking */
  rc = pcap_setnonblock(mp->pt, 1, errbuf);
  if (rc) {

    /* I can't do select() on pcap!
     * blocking + no_select is fatal */
#ifndef PCAP_BSD_SELECT_HACK
    if (mp->pcap_desc < 0)
#endif
    {
      nsock_log_error("Failed to set pcap descriptor on device %s "
                      "to nonblocking mode: %s", pcap_device, errbuf);
      return -1;
    }
    /* in other case, we can accept blocking pcap */
    nsock_log_info("Failed to set pcap descriptor on device %s "
                   "to nonblocking state: %s", pcap_device, errbuf);
  }

  if (NsockLogLevel <= NSOCK_LOG_INFO) {
    #if PCAP_BSD_SELECT_HACK
      int bsd_select_hack = 1;
    #else
      int bsd_select_hack = 0;
    #endif

    #if PCAP_RECV_TIMEVAL_VALID
      int recv_timeval_valid = 1;
    #else
      int recv_timeval_valid = 0;
    #endif

    nsock_log_info("PCAP created successfully on device '%s' "
                   "(pcap_desc=%i bsd_hack=%i to_valid=%i l3_offset=%i) (IOD #%li)",
                   pcap_device, mp->pcap_desc, bsd_select_hack,
                   recv_timeval_valid, mp->l3_offset, nsi->id);
  }
  return 0;
}

/* Requests exactly one packet to be captured. */
nsock_event_id nsock_pcap_read_packet(nsock_pool nsp, nsock_iod nsiod,
                                      nsock_ev_handler handler,
                                      int timeout_msecs, void *userdata) {
  struct niod *nsi = (struct niod *)nsiod;
  struct npool *ms = (struct npool *)nsp;
  struct nevent *nse;

  nse = event_new(ms, NSE_TYPE_PCAP_READ, nsi, timeout_msecs, handler, userdata);
  assert(nse);

  nsock_log_info("Pcap read request from IOD #%li  EID %li", nsi->id, nse->id);

  nsock_pool_add_event(ms, nse);

  return nse->id;
}

/* Remember that pcap descriptor is in nonblocking state. */
int do_actual_pcap_read(struct nevent *nse) {
  mspcap *mp = (mspcap *)nse->iod->pcap;
  nsock_pcap npp;
  nsock_pcap *n;
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt_data = NULL;
  int rc;

  memset(&npp, 0, sizeof(nsock_pcap));

  nsock_log_debug_all("PCAP %s TEST (IOD #%li) (EID #%li)",
                      __func__, nse->iod->id, nse->id);

  assert(fs_length(&(nse->iobuf)) == 0);

  rc = pcap_next_ex(mp->pt, &pkt_header, &pkt_data);
  switch (rc) {
    case 1: /* read good packet  */
#ifdef PCAP_RECV_TIMEVAL_VALID
      npp.ts     = pkt_header->ts;
#else
      /* On these platforms time received from pcap is invalid.
       * It's better to set current time */
      memcpy(&npp.ts, nsock_gettimeofday(), sizeof(struct timeval));
#endif
      npp.len    = pkt_header->len;
      npp.caplen = pkt_header->caplen;
      npp.packet = pkt_data;

      fs_cat(&(nse->iobuf), (char *)&npp, sizeof(npp));
      fs_cat(&(nse->iobuf), (char *)pkt_data, npp.caplen);
      n = (nsock_pcap *)fs_str(&(nse->iobuf));
      n->packet = (unsigned char *)fs_str(&(nse->iobuf)) + sizeof(npp);

      nsock_log_debug_all("PCAP %s READ (IOD #%li) (EID #%li) size=%i",
                          __func__, nse->iod->id, nse->id, pkt_header->caplen);
      rc = 1;
      break;

    case 0: /* timeout */
      rc = 0;
      break;

    case -1: /* error */
      fatal("pcap_next_ex() fatal error while reading from pcap: %s\n",
            pcap_geterr(mp->pt));
      break;

    case -2: /* no more packets in savefile (if reading from one) */
    default:
      fatal("Unexpected return code from pcap_next_ex! (%d)\n", rc);
  }

  return rc;
}

void nse_readpcap(nsock_event nsev, const unsigned char **l2_data, size_t *l2_len,
                  const unsigned char **l3_data, size_t *l3_len,
                  size_t *packet_len, struct timeval *ts) {
  struct nevent *nse = (struct nevent *)nsev;
  struct niod  *iod = nse->iod;
  mspcap *mp = (mspcap *)iod->pcap;
  nsock_pcap *n;
  size_t l2l;
  size_t l3l;

  n = (nsock_pcap *)fs_str(&(nse->iobuf));
  if (fs_length(&(nse->iobuf)) < sizeof(nsock_pcap)) {
    if (l2_data)
      *l2_data = NULL;
    if (l2_len)
      *l2_len = 0;
    if (l3_data)
      *l3_data = NULL;
    if (l3_len)
      *l3_len = 0;
    if (packet_len)
      *packet_len = 0;
    return;
  }

  l2l = MIN(mp->l3_offset, n->caplen);
  l3l = MAX(0, n->caplen-mp->l3_offset);

  if (l2_data)
    *l2_data = n->packet;
  if (l2_len)
    *l2_len = l2l;
  if (l3_data)
    *l3_data = (l3l > 0) ? n->packet+l2l : NULL;
  if (l3_len)
    *l3_len = l3l;
  if (packet_len)
    *packet_len = n->len;
  if (ts)
    *ts = n->ts;
  return;
}

int nsock_iod_linktype(nsock_iod iod) {
  struct niod *nsi = (struct niod *)iod;
  mspcap *mp = (mspcap *)nsi->pcap;

  assert(mp);
  return (mp->datalink);
}

int nsock_iod_is_pcap(nsock_iod iod) {
  struct niod *nsi = (struct niod *)iod;
  mspcap *mp = (mspcap *)nsi->pcap;

  return (mp != NULL);
}

#endif /* HAVE_PCAP */

