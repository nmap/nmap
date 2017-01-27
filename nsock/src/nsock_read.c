/***************************************************************************
 * nsock_read.c -- This contains the functions for requesting various read *
 * events from the nsock parallel socket event library                     *
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

#include "nsock_internal.h"
#include "nsock_log.h"
#include "netutils.h"


/* Read up to nlines lines (terminated with \n, which of course includes \r\n),
 * or until EOF, or until the timeout, whichever comes first.  Note that
 * NSE_STATUS_SUCCESS will be returned in the case of EOF or timeout if at least
 * 1 char has been read.  Also note that you may get more than 'nlines' back --
 * we just stop once "at least" 'nlines' is read */
nsock_event_id nsock_readlines(nsock_pool nsp, nsock_iod ms_iod,
                               nsock_ev_handler handler, int timeout_msecs,
                               void *userdata, int nlines) {
  struct niod *nsi = (struct niod *)ms_iod;
  struct npool *ms = (struct npool *)nsp;
  struct nevent *nse;

  nse = event_new(ms, NSE_TYPE_READ, nsi, timeout_msecs, handler, userdata);
  assert(nse);

  nsock_log_info("Read request for %d lines from IOD #%li [%s] EID %li",
                 nlines, nsi->id, get_peeraddr_string(nsi), nse->id);

  nse->readinfo.read_type = NSOCK_READLINES;
  nse->readinfo.num = nlines;

  nsock_pool_add_event(ms, nse);

  return nse->id;
}

/* Same as above, except it tries to read at least 'nbytes' instead of 'nlines'. */
nsock_event_id nsock_readbytes(nsock_pool nsp, nsock_iod ms_iod,
                               nsock_ev_handler handler, int timeout_msecs,
                               void *userdata, int nbytes) {

  struct niod *nsi = (struct niod *)ms_iod;
  struct npool *ms = (struct npool *)nsp;
  struct nevent *nse;

  nse = event_new(ms, NSE_TYPE_READ, nsi, timeout_msecs, handler, userdata);
  assert(nse);

  nsock_log_info("Read request for %d bytes from IOD #%li [%s] EID %li",
                 nbytes, nsi->id, get_peeraddr_string(nsi), nse->id);

  nse->readinfo.read_type = NSOCK_READBYTES;
  nse->readinfo.num = nbytes;

  nsock_pool_add_event(ms, nse);

  return nse->id;
}


/* The simplest read function -- returns NSE_STATUS_SUCCESS when it
 * reads anything, otherwise it returns timeout, eof, or error as appropriate */
nsock_event_id nsock_read(nsock_pool nsp, nsock_iod ms_iod,
                          nsock_ev_handler handler, int timeout_msecs,
                          void *userdata) {
  struct niod *nsi = (struct niod *)ms_iod;
  struct npool *ms = (struct npool *)nsp;
  struct nevent *nse;

  nse = event_new(ms, NSE_TYPE_READ, nsi, timeout_msecs, handler, userdata);
  assert(nse);

  nsock_log_info("Read request from IOD #%li [%s] (timeout: %dms) EID %li",
                 nsi->id, get_peeraddr_string(nsi), timeout_msecs, nse->id);

  nse->readinfo.read_type = NSOCK_READ;

  nsock_pool_add_event(ms, nse);

  return nse->id;
}

