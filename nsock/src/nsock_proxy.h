/***************************************************************************
 * nsock_proxy.h -- PRIVATE interface definitions for proxy handling.      *
 *                                                                         *
 ***********************IMPORTANT NSOCK LICENSE TERMS***********************
 *                                                                         *
 * The nsock parallel socket event library is (C) 1999-2013 Insecure.Com   *
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

#ifndef NSOCK_PROXY_H
#define NSOCK_PROXY_H

#include "gh_list.h"

#if HAVE_NETDB_H
#include <netdb.h>
#endif

#include <nsock.h>
#include <errno.h>


/* ------------------- CONSTANTS ------------------- */
enum nsock_proxy_type {
  PROXY_TYPE_HTTP = 0,
  PROXY_TYPE_SOCKS4,
  PROXY_TYPE_COUNT,
};

enum nsock_proxy_state {
  /* Common initial state for all proxy types. */
  PROXY_STATE_INITIAL,

  /* HTTP proxy states. */
  PROXY_STATE_HTTP_TCP_CONNECTED,
  PROXY_STATE_HTTP_TUNNEL_ESTABLISHED,

  /* SOCKS 4 proxy states. */
  PROXY_STATE_SOCKS4_TCP_CONNECTED,
  PROXY_STATE_SOCKS4_TUNNEL_ESTABLISHED,
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
  const struct proxy_spec *spec;

  struct sockaddr_storage ss;
  size_t sslen;
  unsigned short port;
  char *nodestr; /* used for log messages */
};

/* Ordered list of proxy nodes, as specified in the proxy specification string. */
struct proxy_chain {
  gh_list nodes;
};

/* IOD-specific context. For each IOD we establish a tunnel through the chain of
 * proxies. This structure stores all the related information. */
struct proxy_chain_context {
  const struct proxy_chain *px_chain;

  /* Nodes iterator in px_chain->nodes */
  gh_list_elem *px_current;
  
  /* Current node connection state. */
  enum nsock_proxy_state px_state;

  /* Those fields are used to store information about the final target
   * to reach. */
  enum nse_type target_ev_type;
  struct sockaddr_storage target_ss;
  size_t target_sslen;
  unsigned short target_port;
  nsock_ev_handler target_handler;
};

struct proxy_op {
  int (*node_new)(struct proxy_node **node, const struct uri *uri);
  void (*node_delete)(struct proxy_node *node);
  void (*handler)(nsock_pool nspool, nsock_event nsevent, void *udata);
};

struct proxy_spec {
  const char *prefix;
  enum nsock_proxy_type type;
  const struct proxy_op *ops;
};


/* ------------------- UTIL FUNCTIONS ------------------- */
int proxy_resolve(const char *host, struct sockaddr *addr, size_t *addrlen);

static inline struct proxy_node *proxy_ctx_node_current(struct proxy_chain_context *ctx) {
  return (struct proxy_node *)GH_LIST_ELEM_DATA(ctx->px_current);
}

static inline struct proxy_node *proxy_ctx_node_next(struct proxy_chain_context *ctx) {
  gh_list_elem *next;

  next = GH_LIST_ELEM_NEXT(ctx->px_current);
  if (next)
    return (struct proxy_node *)GH_LIST_ELEM_DATA(next);

  return NULL;
}


/* ------------------- PROTOTYPES ------------------- */

struct proxy_chain_context *proxy_chain_context_new(nsock_pool nspool);
void proxy_chain_context_delete(struct proxy_chain_context *ctx);

void nsock_proxy_ev_dispatch(nsock_pool nspool, nsock_event nsevent, void *udata);
void forward_event(nsock_pool nspool, nsock_event nse, void *udata);


#endif /* NSOCK_PROXY_H */

