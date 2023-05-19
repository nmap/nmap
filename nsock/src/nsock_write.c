/***************************************************************************
 * nsock_write.c -- This contains the functions relating to writing to     *
 * sockets using the nsock parallel socket event library                   *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *
 * The nsock parallel socket event library is (C) 1999-2023 Nmap Software LLC
 * This library is free software; you may redistribute and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; Version 2. This guarantees your right to use, modify, and
 * redistribute this software under certain conditions. If this license is
 * unacceptable to you, Nmap Software LLC may be willing to sell alternative
 * licenses (contact sales@nmap.com ).
 *
 * As a special exception to the GPL terms, Nmap Software LLC grants permission
 * to link the code of this program with any version of the OpenSSL library
 * which is distributed under a license identical to that listed in the included
 * docs/licenses/OpenSSL.txt file, and distribute linked combinations including
 * the two. You must obey the GNU GPL in all respects for all of the code used
 * other than OpenSSL. If you modify this file, you may extend this exception to
 * your version of the file, but you are not obligated to do so.
 *
 * If you received these files with a written license agreement stating terms
 * other than the (GPL) terms above, then that alternative license agreement
 * takes precedence over this comment.
 *
 * Source is provided to this software because we believe users have a right to
 * know exactly what a program is going to do before they run it. This also
 * allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to send your changes to the
 * dev@nmap.org mailing list for possible incorporation into the main
 * distribution. By sending these changes to Fyodor or one of the Insecure.Org
 * development mailing lists, or checking them into the Nmap source code
 * repository, it is understood (unless you specify otherwise) that you are
 * offering the Nmap Project (Nmap Software LLC) the unlimited, non-exclusive
 * right to reuse, modify, and relicense the code. Nmap will always be available
 * Open Source, but this is important because the inability to relicense code
 * has caused devastating problems for other Free Software projects (such as KDE
 * and NASM). We also occasionally relicense the code to third parties as
 * discussed above. If you wish to specify special license conditions of your
 * contributions, just say so when you send them.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License v2.0 for more
 * details (http://www.gnu.org/licenses/gpl-2.0.html).
 *
 ***************************************************************************/

/* $Id$ */

#include "nsock.h"
#include "nsock_internal.h"
#include "nsock_log.h"
#include "netutils.h"

#include <nbase.h>
#include <stdarg.h>
#include <errno.h>

nsock_event_id nsock_sendto(nsock_pool ms_pool, nsock_iod ms_iod, nsock_ev_handler handler, int timeout_msecs,
                            void *userdata, struct sockaddr *saddr, size_t sslen, unsigned short port, const char *data, int datalen) {
  struct npool *nsp = (struct npool *)ms_pool;
  struct niod *nsi = (struct niod *)ms_iod;
  struct nevent *nse;
  char displaystr[256];
  struct sockaddr_in *sin = (struct sockaddr_in *)saddr;
#if HAVE_IPV6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)saddr;
#endif

  nse = event_new(nsp, NSE_TYPE_WRITE, nsi, timeout_msecs, handler, userdata);
  assert(nse);

  if (saddr->sa_family == AF_INET) {
    sin->sin_port = htons(port);
#if HAVE_SYS_UN_H
  } else if (saddr->sa_family == AF_INET6) {
#else
  } else {
#endif
    assert(saddr->sa_family == AF_INET6);
#if HAVE_IPV6
    sin6->sin6_port = htons(port);
#else
    fatal("IPv6 address passed to %s call, but nsock was not compiled w/IPv6 support", __func__);
#endif
  }

  assert(sslen <= sizeof(nse->writeinfo.dest));
  memcpy(&nse->writeinfo.dest, saddr, sslen);
  nse->writeinfo.destlen = sslen;

  assert(sslen <= sizeof(nse->iod->peer));
  memcpy(&nse->iod->peer, saddr, sslen);
  nse->iod->peerlen = sslen;

  if (datalen < 0)
    datalen = (int) strlen(data);

  if (NsockLogLevel == NSOCK_LOG_DBG_ALL && datalen < 80) {
    memcpy(displaystr, ": ", 2);
    memcpy(displaystr + 2, data, datalen);
    displaystr[2 + datalen] = '\0';
    replacenonprintable(displaystr + 2, datalen, '.');
  } else {
    displaystr[0] = '\0';
  }
  nsock_log_info("Sendto request for %d bytes to IOD #%li EID %li [%s]%s",
                 datalen, nsi->id, nse->id, get_peeraddr_string(nse->iod),
                 displaystr);

  fs_cat(&nse->iobuf, data, datalen);

  nsock_pool_add_event(nsp, nse);

  return nse->id;
}

/* Write some data to the socket.  If the write is not COMPLETED within
 * timeout_msecs , NSE_STATUS_TIMEOUT will be returned.  If you are supplying
 * NUL-terminated data, you can optionally pass -1 for datalen and nsock_write
 * will figure out the length itself */
nsock_event_id nsock_write(nsock_pool ms_pool, nsock_iod ms_iod,
          nsock_ev_handler handler, int timeout_msecs, void *userdata, const char *data, int datalen) {
  struct npool *nsp = (struct npool *)ms_pool;
  struct niod *nsi = (struct niod *)ms_iod;
  struct nevent *nse;
  char displaystr[256];

  nse = event_new(nsp, NSE_TYPE_WRITE, nsi, timeout_msecs, handler, userdata);
  assert(nse);

  nse->writeinfo.dest.ss_family = AF_UNSPEC;

  if (datalen < 0)
    datalen = (int)strlen(data);

  if (NsockLogLevel == NSOCK_LOG_DBG_ALL && datalen < 80) {
    memcpy(displaystr, ": ", 2);
    memcpy(displaystr + 2, data, datalen);
    displaystr[2 + datalen] = '\0';
    replacenonprintable(displaystr + 2, datalen, '.');
  } else {
    displaystr[0] = '\0';
  }

  nsock_log_info("Write request for %d bytes to IOD #%li EID %li [%s]%s",
      datalen, nsi->id, nse->id, get_peeraddr_string(nsi),
      displaystr);

  fs_cat(&nse->iobuf, data, datalen);

  nsock_pool_add_event(nsp, nse);

  return nse->id;
}

/* Same as nsock_write except you can use a printf-style format and you can only use this for ASCII strings */
nsock_event_id nsock_printf(nsock_pool ms_pool, nsock_iod ms_iod,
          nsock_ev_handler handler, int timeout_msecs, void *userdata, char *format, ...) {
  struct npool *nsp = (struct npool *)ms_pool;
  struct niod *nsi = (struct niod *)ms_iod;
  struct nevent *nse;
  char buf[4096];
  char *buf2 = NULL;
  size_t buf2size;
  int res, res2;
  int strlength = 0;
  char displaystr[256];

  va_list ap;

  nse = event_new(nsp, NSE_TYPE_WRITE, nsi, timeout_msecs, handler, userdata);
  assert(nse);

  va_start(ap,format);
  res = Vsnprintf(buf, sizeof(buf), format, ap);
  va_end(ap);

  if (res >= 0) {
    if (res >= sizeof(buf)) {
      buf2size = res + 16;
      buf2 = (char * )safe_malloc(buf2size);
      va_start(ap,format);
      res2 = Vsnprintf(buf2, buf2size, format, ap);
      va_end(ap);
      if (res2 < 0 || (size_t) res2 >= buf2size) {
        free(buf2);
        buf2 = NULL;
      } else
        strlength = res2;
    } else {
      buf2 = buf;
      strlength = res;
    }
  }

  if (!buf2) {
    nse->event_done = 1;
    nse->status = NSE_STATUS_ERROR;
    nse->errnum = EMSGSIZE;
  } else {
    if (strlength == 0) {
      nse->event_done = 1;
      nse->status = NSE_STATUS_SUCCESS;
    } else {
      fs_cat(&nse->iobuf, buf2, strlength);
    }
  }

  if (NsockLogLevel == NSOCK_LOG_DBG_ALL &&
      nse->status != NSE_STATUS_ERROR &&
      strlength < 80) {
    memcpy(displaystr, ": ", 2);
    memcpy(displaystr + 2, buf2, strlength);
    displaystr[2 + strlength] = '\0';
    replacenonprintable(displaystr + 2, strlength, '.');
  } else {
    displaystr[0] = '\0';
  }

  nsock_log_info("Write request for %d bytes to IOD #%li EID %li [%s]%s",
                 strlength, nsi->id, nse->id, get_peeraddr_string(nsi),
                 displaystr);

  if (buf2 != buf)
    free(buf2);

  nsock_pool_add_event(nsp, nse);

  return nse->id;
}

