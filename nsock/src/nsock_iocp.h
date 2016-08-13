/***************************************************************************
 * nsock_iocp.h -- Header for the overlapped operations in nsock_iocp.c.   *
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

#ifndef NSOCK_IOCP_H
#define NSOCK_IOCP_H

#include "nsock_internal.h"
#ifdef HAVE_IOCP

/*
 * Engine specific data structure
 */
struct iocp_engine_info {
  /* The handle to the Completion Port*/
  HANDLE iocp;

  /* We put the current eov to be processed here in order to be retrieved by nsock_core */
  struct extended_overlapped *eov;

  /* The overlapped_entry list used to retrieve completed packets from the port */
  OVERLAPPED_ENTRY *eov_list;
  unsigned long capacity;

  /* How many Completion Packets we actually retreieved */
  unsigned long entries_removed;
};

struct extended_overlapped {
  /* Overlapped structure used for overlapped operations */
  OVERLAPPED ov;

  /* Did we get an error when we initiated the operation?
  Put the error code here and post it to the main loop */
  int err;

  /* The event may have expired and was recycled, we can't trust
  a pointer to the nevent structure to tell us the real nevent */
  nsock_event_id nse_id;

  /* A pointer to the event */
  struct nevent *nse;

  /* Needed for WSARecv/WSASend */
  WSABUF wsabuf;

  /* This is the buffer we will read data in */
  char *readbuf;

  /* The struct npool keeps track of EOVs that have been allocated so that it
  * can destroy them if the msp is deleted.  This pointer makes it easy to
  * remove this struct extended_overlapped from the allocated list when necessary */
  gh_lnode_t nodeq;

};


void initiate_overlapped_event(struct npool *nsp, struct nevent *nse);

void terminate_overlapped_event(struct npool *nsp, struct nevent *nse);

int get_overlapped_result(struct niod *iod, struct nevent *nse, char *buf);

void free_eov(struct npool *nsp, struct extended_overlapped *eov);

#endif /* HAVE_IOCP */
#endif /* NSOCK_IOCP_H */
