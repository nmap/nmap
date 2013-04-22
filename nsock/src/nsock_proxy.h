/***************************************************************************
 * nsock_proxy.h -- PRIVATE interface definitions for proxy handling.      *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2012 Insecure.Com   *
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
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details                            *
 * (http://www.gnu.org/licenses/gpl-2.0.html).                             *
 *                                                                         *
 ***************************************************************************/

/* $Id: $ */

#ifndef NSOCK_PROXY_H
#define NSOCK_PROXY_H

#include "gh_list.h"
#include <nsock.h>


/* ------------------ UTIL MACROS ------------------ */
#define PROXY_CTX_CURRENT(ctx) ((struct proxy_node *)(GH_LIST_ELEM_DATA((ctx)->px_current)))
#define PROXY_CTX_NEXT(ctx) ((struct proxy_node *)((GH_LIST_ELEM_NEXT((ctx)->px_current)) ? GH_LIST_ELEM_DATA(GH_LIST_ELEM_NEXT((ctx)->px_current)) : NULL))
#define PROXY_CTX_NODES(ctx) ((ctx)->px_chain->nodes)


/* ------------------- CONSTANTS ------------------- */
enum nsock_proxy_type {
  PROXY_TYPE_HTTP = 0,
  PROXY_TYPE_COUNT,
};

enum nsock_proxy_state {
  /* Common initial state for all proxy types. */
  PROXY_STATE_INITIAL,

  /* HTTP proxy states. */
  PROXY_STATE_HTTP_TCP_CONNECTED,
  PROXY_STATE_HTTP_TUNNEL_ESTABLISHED
};


/* ------------------- STRUCTURES ------------------- */

struct uri {
  char *scheme;
  char *user;
  char *pass;
  char *host;
  char *path;
  int port;
};

/* Static information about a proxy node in the chain. This is generated by
 * parsing the proxy specification string given by user. Those structures are
 * then read-only and stored in the nsock_pool. */
struct proxy_node {
  enum nsock_proxy_type px_type;

  const struct proxy_op *ops;

  struct sockaddr_storage ss;
  size_t sslen;
  unsigned short port;
};

/* Ordered list of proxy nodes, as specified in the proxy specification string. */
struct proxy_chain {
  char *specstr;
  gh_list nodes;
};

/* IOD-specific context. For each IOD we establish a tunnel through the chain of
 * proxies. This structure stores all the related information. */
struct proxy_chain_context {
  const struct proxy_chain *px_chain;

  /* Those fields are used to store current state during the tunnel
   * establishment phase. */
  gh_list_elem *px_current;
  enum nsock_proxy_state px_state;

  /* Each proxy in the chain maintains a data structure. This can contains r/w
   * buffers for instance. */
  gh_list px_info;

  struct sockaddr_storage target_ss;
  size_t target_sslen;
  unsigned short target_port;
  nsock_ev_handler target_handler;
};

struct proxy_op {
  const char *prefix;
  enum nsock_proxy_type type;

  int (*node_new)(struct proxy_node **node, const struct uri *uri);
  void (*node_delete)(struct proxy_node *node);

  int (*info_new)(void **info);
  void (*info_delete)(void *info);

  void (*handler)(nsock_pool nspool, nsock_event nsevent, void *udata);

  char *(*encode)(const char *src, size_t len, size_t *dlen);
  char *(*decode)(const char *src, size_t len, size_t *dlen);
};


/* ------------------- PROTOTYPES ------------------- */

struct proxy_chain_context *proxy_chain_context_new(nsock_pool nspool);
void proxy_chain_context_delete(struct proxy_chain_context *ctx);

void nsock_proxy_ev_dispatch(nsock_pool nspool, nsock_event nsevent, void *udata);
void forward_event(nsock_pool nspool, nsock_event nse, void *udata);


#endif /* NSOCK_PROXY_H */

