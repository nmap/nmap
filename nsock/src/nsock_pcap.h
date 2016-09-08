/***************************************************************************
 * nsock_pcap.h -- Header for pcap operations functions from               *
 * the nsock parallel socket event library                                 *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2016 Insecure.Com   *
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

#ifndef NSOCK_PCAP_H
#define NSOCK_PCAP_H

#include "nsock_internal.h"
#ifdef HAVE_PCAP

#include "pcap.h"

#include <string.h>
#include <stdarg.h>

#ifdef WIN32
/* WinPCAP doesn't have this, but Npcap does.
 * Using 0 is safe for both, but change this if we decide to drop WinPcap */
#undef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0
#endif

/*
 * There are three possible ways to read packets from pcap descriptor:
 *  - select() on descriptor:
 *      this one is of course the best, but there are systems that
 *      don't support this like WIN32. This works perfectly for Linux.
 *
 *  - select() + some hacks:
 *      this one is hack for older bsd systems,
 *      Descriptor *must* be set in nonblocking mode.
 *
 *   - never do select():
 *      this one is for WIN32 and other systems that return descriptor -1
 *      from pcap_get_selectable_fd().
 *      In this case descriptor *must* be set in nonblocking mode.
 *      If that fails than we can't do any sniffing from that box.
 *
 * In any case we try to set descriptor to non-blocking mode.
 */

/* Returns whether the system supports pcap_get_selectable_fd() properly */
#if !defined(WIN32) && !defined(SOLARIS_BPF_PCAP_CAPTURE)
#define PCAP_CAN_DO_SELECT 1
#endif

/* In some systems (like Windows), the pcap descriptor is not selectable.
 * Therefore, we cannot just select() on it and expect it to wake us up and
 * deliver a packet, but we need to poll it continuously. This define sets the
 * frequency, in milliseconds, at which the pcap handle is polled to determine
 * if there are any captured packets.  Note that this is only used when
 * PCAP_CAN_DO_SELECT is not defined and therefore it has no effect on systems
 * like Linux.
 */
#define PCAP_POLL_INTERVAL 2

/* Note that on most versions of most BSDs (including Mac OS X) select() and
 * poll() do not work correctly on BPF devices; pcap_get_selectable_fd() will
 * return a file descriptor on most of those versions (the exceptions being
 * FreeBSD 4.3 and 4.4), a simple select() or poll() will not return even after
 * a timeout specified in pcap_open_live() expires. To work around this, an
 * application that uses select() or poll() to wait for packets to arrive must
 * put the pcap_t in non-blocking mode, and must arrange that the select() or
 * poll() have a timeout less than or equal to the timeout specified in
 * pcap_open_live(), and must try to read packets after that timeout expires,
 * regardless of whether select() or poll() indicated that the file descriptor
 * for the pcap_t is ready to be read or not. (That workaround will not work in
 * FreeBSD 4.3 and later; however, in FreeBSD 4.6 and later, select() and poll()
 * work correctly on BPF devices, so the workaround isn't necessary, although it
 * does no harm.)
 */
#if defined(MACOSX) || defined(FREEBSD) || defined(OPENBSD)
/* Well, now select() is not receiving any pcap events on MACOSX, but maybe it
 * will someday :) in both cases. It never hurts to enable this feature. It just
 * has performance penalty. */
#define PCAP_BSD_SELECT_HACK 1
#endif

/* Returns whether the packet receive time value obtained from libpcap
 * (and thus by readip_pcap()) should be considered valid.  When
 * invalid (Windows and Amiga), readip_pcap returns the time you called it. */
#if !defined(WIN32) && !defined(__amigaos__)
#define PCAP_RECV_TIMEVAL_VALID 1
#endif


typedef struct{
  pcap_t *pt;
  int pcap_desc;
  /* Like the corresponding member in iod, when this reaches 0 we stop
   * watching the socket for readability. */
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
  const unsigned char *packet;  /* caplen bytes */
} nsock_pcap;

int do_actual_pcap_read(struct nevent *nse);

#endif /* HAVE_PCAP */
#endif /* NSOCK_PCAP_H */

