/***************************************************************************
 * proxy_socks4a.c -- SOCKS4A proxying.                                      *
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

/* $Id $ */

#define _GNU_SOURCE
#include <stdio.h>

#include "nsock.h"
#include "nsock_internal.h"
#include "nsock_log.h"

#include <string.h>

#define DEFAULT_PROXY_PORT_SOCKS4A 9050

extern struct timeval nsock_tod;
extern const struct proxy_spec ProxySpecSocks4a;

/* This is the same data type as socks4_data
 * __attribute__((packed)) must be used or an extra 3 bytes gets allocated */
struct socks4a_data {
  uint8_t version;
  uint8_t type;
  uint16_t port;
  uint32_t address;
  uint8_t null;
}__attribute__((packed));

static int proxy_socks4a_node_new(struct proxy_node **node, const struct uri *uri) {
  int rc;
  struct proxy_node *proxy;

  proxy = (struct proxy_node *)safe_zalloc(sizeof(struct proxy_node));
  proxy->spec = &ProxySpecSocks4a;

  rc = proxy_resolve(uri->host, (struct sockaddr *)&proxy->ss, &proxy->sslen);
  if (rc < 0)
    goto err_out;

  if (proxy->ss.ss_family != AF_INET) {
    rc = -1;
    goto err_out;
  }

  if (uri->port == -1)
    proxy->port = DEFAULT_PROXY_PORT_SOCKS4A;
  else
    proxy->port = (unsigned short)uri->port;

  rc = asprintf(&proxy->nodestr, "socks4a://%s:%d", uri->host, proxy->port);
  if (rc < 0) {
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

static void proxy_socks4a_node_delete(struct proxy_node *node)
{
  if (!node)
    return;

  if (node->nodestr)
    free(node->nodestr);

  free(node);
}


static void socks4a_data_init(struct socks4a_data *socks4a,
                              unsigned short port) {
  memset(socks4a, 0x00, sizeof(struct socks4a_data));
  socks4a->version = 4;
  socks4a->type = 1;
  socks4a->port = htons(port);
  /* This is address 0.0.0.255, necessary for socks4a to accept target_name */
  socks4a->address = htonl(0xff);
}

static int handle_state_init_socks4a(struct npool *nsp, struct nevent *nse,
                                     void *udata) {
  struct proxy_chain_context *px_ctx = nse->iod->px_ctx;
  struct socks4a_data socks4a;
  socks4a_data_init(&socks4a, px_ctx->target_port);
  char *target_name = nse->iod->hostname;
  int target_name_len = strlen(target_name);
  int timeout;
  uint8_t nullbyte = '\0';

  px_ctx->px_state = PROXY_STATE_SOCKS4A_TCP_CONNECTED;

  size_t outgoing_len = sizeof(struct socks4a_data) + target_name_len
                               + sizeof(uint8_t);

  uint8_t *outgoing = safe_zalloc(outgoing_len);

  /* copy socks4a structure into the memory */
  memcpy(outgoing, &socks4a, sizeof(socks4a));

  /* copy the target name immediately after socks4a
   * calloc makes last byte null */
  memcpy(outgoing + sizeof(struct socks4a_data), target_name,
         target_name_len);

  memcpy(outgoing + sizeof(struct socks4a_data) + target_name_len, &nullbyte,
         sizeof(uint8_t));

  timeout = TIMEVAL_MSEC_SUBTRACT(nse->timeout, nsock_tod);

  nsock_write(nsp, (nsock_iod)nse->iod, nsock_proxy_ev_dispatch, timeout, udata,
              (char *)outgoing, outgoing_len);

  nsock_readbytes(nsp, (nsock_iod)nse->iod, nsock_proxy_ev_dispatch, timeout,
                  udata, 8);

  /* freeing the allocated memory */
  free(outgoing);

  return 0;
}

static int handle_state_tcp_socks4a(struct npool *nsp, struct nevent *nse,
                                    void *udata) {
  struct proxy_chain_context *px_ctx = nse->iod->px_ctx;
  char *res;
  int reslen;

  res = nse_readbuf(nse, &reslen);

  if (!(reslen == 8 && res[1] == 90)) {
    struct proxy_node *node = px_ctx->px_current;

    nsock_log_debug(nsp, "Ignoring invalid socks4a reply from proxy %s",
                    node->nodestr);
    return -EINVAL;
  }

  px_ctx->px_state = PROXY_STATE_SOCKS4A_TUNNEL_ESTABLISHED;

  if (proxy_ctx_node_next(px_ctx) == NULL) {
    forward_event(nsp, nse, udata);
  } else {
    px_ctx->px_current = proxy_ctx_node_next(px_ctx);
    px_ctx->px_state = PROXY_STATE_INITIAL;
    nsock_proxy_ev_dispatch(nsp, nse, udata);
  }
  return 0;
}

static void proxy_socks4a_handler(nsock_pool nspool, nsock_event nsevent,
                                  void *udata) {
  int rc = 0;
  struct npool *nsp = (struct npool *)nspool;
  struct nevent *nse = (struct nevent *)nsevent;

  switch (nse->iod->px_ctx->px_state) {
    case PROXY_STATE_INITIAL:
      rc = handle_state_init_socks4a(nsp, nse, udata);
      break;

    case PROXY_STATE_SOCKS4A_TCP_CONNECTED:
      if (nse->type == NSE_TYPE_READ)
        rc = handle_state_tcp_socks4a(nsp, nse, udata);
      break;

    case PROXY_STATE_SOCKS4A_TUNNEL_ESTABLISHED:
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
static const struct proxy_op ProxyOpsSocks4a = {
  proxy_socks4a_node_new,
  proxy_socks4a_node_delete,
  proxy_socks4a_handler,
};

const struct proxy_spec ProxySpecSocks4a = {
  "socks4a://",
  PROXY_TYPE_SOCKS4A,
  &ProxyOpsSocks4a,
};

