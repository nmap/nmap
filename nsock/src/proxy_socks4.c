/***************************************************************************
 * proxy_socks4.c -- SOCKS4 proxying.                                      *
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

/* $Id $ */

#define _GNU_SOURCE
#include <stdio.h>

#include "nsock.h"
#include "nsock_internal.h"
#include "nsock_log.h"

#include <string.h>

#define DEFAULT_PROXY_PORT_SOCKS4 1080


extern struct timeval nsock_tod;
extern const struct proxy_spec ProxySpecSocks4;


struct socks4_data {
    uint8_t  version;
    uint8_t  type;
    uint16_t port;
    uint32_t address;
    uint8_t  null;
} __attribute__((packed));


static int proxy_socks4_node_new(struct proxy_node **node, const struct uri *uri) {
  int rc;
  struct proxy_node *proxy;

  proxy = (struct proxy_node *)safe_zalloc(sizeof(struct proxy_node));
  proxy->spec = &ProxySpecSocks4;

  rc = proxy_resolve(uri->host, (struct sockaddr *)&proxy->ss, &proxy->sslen, AF_INET);
  if (rc < 0)
    goto err_out;

  if (proxy->ss.ss_family != AF_INET) {
    rc = -1;
    goto err_out;
  }

  if (uri->port == -1)
    proxy->port = DEFAULT_PROXY_PORT_SOCKS4;
  else
    proxy->port = (unsigned short)uri->port;

  rc = asprintf(&proxy->nodestr, "socks4://%s:%d", uri->host, proxy->port);
  if (rc < 0) {
    /* asprintf() failed for some reason but this is not a disaster (yet).
     * Set nodestr to NULL and try to keep on going. */
    proxy->nodestr = NULL;
  }

  rc = 1;

err_out:
  if (rc < 0) {
    free(proxy);
    proxy = NULL;
  }
  *node = proxy;
  return rc;
}

static void proxy_socks4_node_delete(struct proxy_node *node) {
  if (!node)
    return;

  free(node->nodestr);

  free(node);
}

static inline void socks4_data_init(struct socks4_data *socks4,
                                    struct sockaddr_storage *ss, size_t sslen,
                                    unsigned short port) {
  struct sockaddr_in *sin = (struct sockaddr_in *)ss;

  memset(socks4, 0x00, sizeof(struct socks4_data));
  socks4->version = 4;
  socks4->type = 1;
  socks4->port = htons(port);
  assert(ss->ss_family == AF_INET);
  socks4->address = sin->sin_addr.s_addr;
}

static int handle_state_initial(struct npool *nsp, struct nevent *nse, void *udata) {
  struct proxy_chain_context *px_ctx = nse->iod->px_ctx;
  struct sockaddr_storage *ss;
  size_t sslen;
  unsigned short port;
  struct proxy_node *next;
  struct socks4_data socks4;
  int timeout;

  px_ctx->px_state = PROXY_STATE_SOCKS4_TCP_CONNECTED;

  next = proxy_ctx_node_next(px_ctx);
  if (next) {
    ss    = &next->ss;
    sslen = next->sslen;
    port  = next->port;
  } else {
    ss    = &px_ctx->target_ss;
    sslen = px_ctx->target_sslen;
    port  = px_ctx->target_port;
  }

  socks4_data_init(&socks4, ss, sslen, port);

  timeout = TIMEVAL_MSEC_SUBTRACT(nse->timeout, nsock_tod);

  nsock_write(nsp, (nsock_iod)nse->iod, nsock_proxy_ev_dispatch, timeout, udata,
              (char *)&socks4, sizeof(socks4));

  nsock_readbytes(nsp, (nsock_iod)nse->iod, nsock_proxy_ev_dispatch, timeout,
                  udata, 8);
  return 0;
}

static int handle_state_tcp_connected(struct npool *nsp, struct nevent *nse, void *udata) {
  struct proxy_chain_context *px_ctx = nse->iod->px_ctx;
  char *res;
  int reslen;

  res = nse_readbuf(nse, &reslen);

  if (!(reslen == 8 && res[1] == 90)) {
    struct proxy_node *node = px_ctx->px_current;

    nsock_log_debug("Ignoring invalid socks4 reply from proxy %s",
                    node->nodestr);
    return -EINVAL;
  }

  px_ctx->px_state = PROXY_STATE_SOCKS4_TUNNEL_ESTABLISHED;

  if (proxy_ctx_node_next(px_ctx) == NULL) {
    forward_event(nsp, nse, udata);
  } else {
    px_ctx->px_current = proxy_ctx_node_next(px_ctx);
    px_ctx->px_state   = PROXY_STATE_INITIAL;
    nsock_proxy_ev_dispatch(nsp, nse, udata);
  }
  return 0;
}

static void proxy_socks4_handler(nsock_pool nspool, nsock_event nsevent, void *udata) {
  int rc = 0;
  struct npool *nsp = (struct npool *)nspool;
  struct nevent *nse = (struct nevent *)nsevent;

  switch (nse->iod->px_ctx->px_state) {
    case PROXY_STATE_INITIAL:
      rc = handle_state_initial(nsp, nse, udata);
      break;

    case PROXY_STATE_SOCKS4_TCP_CONNECTED:
      if (nse->type == NSE_TYPE_READ)
        rc = handle_state_tcp_connected(nsp, nse, udata);
      break;

    case PROXY_STATE_SOCKS4_TUNNEL_ESTABLISHED:
      forward_event(nsp, nse, udata);
      break;

    default:
      fatal("Invalid proxy state!");
  }

  if (rc) {
    nse->status = NSE_STATUS_PROXYERROR;
    forward_event(nsp, nse, udata);
  }
}

/* ---- PROXY DEFINITION ---- */
static const struct proxy_op ProxyOpsSocks4 = {
  proxy_socks4_node_new,
  proxy_socks4_node_delete,
  proxy_socks4_handler,
};

const struct proxy_spec ProxySpecSocks4 = {
  "socks4://",
  PROXY_TYPE_SOCKS4,
  &ProxyOpsSocks4,
};

