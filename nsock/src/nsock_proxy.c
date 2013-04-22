/***************************************************************************
 * nsock_proxy.c -- This contains the functions relating to proxies.       *
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

/* $Id $ */

#include "nsock.h"
#include "nsock_internal.h"
#include <netdb.h>
#include <string.h>

/* TODO first!
 * ---
 *   o Parse proxy spec string
 *   o Deal with actual proxy chains (cf. ev_handler)
 *   o Deal with errors
 *   o Generic proxy interface (to handle many proxy types)
 * ---
 *   o Manage timeouts
 */

struct proxy_parser {
  int done;
  struct proxy_node *value;
  char *str;
  char *saveptr;
  char *tokens;
};


static struct proxy_parser *proxy_parser_new(const char *proxychainstr);
static void proxy_parser_next(struct proxy_parser *parser);
static void proxy_parser_delete(struct proxy_parser *parser);

static struct proxy_node *proxy_node_new(char *proxystr);
static void proxy_node_delete(struct proxy_node *proxy);

static void forward_event(mspool *nsp, msevent *nse, void *udata);

static void proxy_http_node_init(struct proxy_node *proxy, char *proxystr);
static void proxy_http_ev_handler(nsock_pool nspool, nsock_event nsevent, void *udata);


static nsock_event_id proxy_http_connect_tcp(nsock_pool nsp, nsock_iod ms_iod, nsock_ev_handler handler,
                                             int timeout_msecs, void *userdata, struct sockaddr *saddr,
                                             size_t sslen, unsigned short port);
static  char *proxy_http_data_encode(const char *src, size_t len, size_t *dlen);
static  char *proxy_http_data_decode(const char *src, size_t len, size_t *dlen);


const struct proxy_actions ProxyActions[PROXY_TYPE_COUNT] = {
  [PROXY_TYPE_HTTP] = {
    .connect_tcp = proxy_http_connect_tcp,
    .data_encode = proxy_http_data_encode,
    .data_decode = proxy_http_data_decode
  }
};


/* A proxy chain is a comma-separated list of proxy specification strings:
 * proto://[user:pass@]host[:port] */
int nsock_proxychain_new(const char *proxystr, nsock_proxychain *chain, nsock_pool nspool) {
  mspool *nsp = (mspool *)nspool;
  struct proxy_chain **pchain = (struct proxy_chain **)chain;

  *pchain = (struct proxy_chain *)safe_malloc(sizeof(struct proxy_chain));
  (*pchain)->specstr = strdup(proxystr);
  gh_list_init(&(*pchain)->nodes);

  if (proxystr) {
    struct proxy_parser *parser;

    for (parser = proxy_parser_new(proxystr); !parser->done; proxy_parser_next(parser)) {
      gh_list_append(&(*pchain)->nodes, parser->value);
    }
    proxy_parser_delete(parser);
  }

  if (nsp) {
    if (nsp_set_proxychain(nspool, *pchain) < 0) {
      nsock_proxychain_delete(*pchain);
      return -1;
    }
  }

  return 0;
}

void nsock_proxychain_delete(nsock_proxychain chain) {
  struct proxy_chain *pchain = (struct proxy_chain *)chain;

  if (pchain) {
    struct proxy_node *node;

    free(pchain->specstr);
    while ((node = (struct proxy_node *)gh_list_pop(&pchain->nodes)) != NULL) {
      proxy_node_delete(node);
    }

    gh_list_free(&pchain->nodes);
    free(pchain);
  }
}

int nsp_set_proxychain(nsock_pool nspool, nsock_proxychain chain) {
  mspool *nsp = (mspool *)nspool;

  if (nsp && nsp->px_chain) {
    nsock_trace(nsp, "Invalid call to %s. Existing proxychain on this nsock_pool", __func__);
    return -1;
  }

  nsp->px_chain = (struct proxy_chain *)chain;
  return 0;
}


struct proxy_chain_context *proxy_chain_context_new(nsock_pool nspool) {
  mspool *nsp = (mspool *)nspool;
  struct proxy_chain_context *ctx;

  ctx = (struct proxy_chain_context *)safe_malloc(sizeof(struct proxy_chain_context));
  ctx->px_state = PROXY_STATE_INITIAL;
  ctx->px_current = GH_LIST_FIRST_ELEM(&nsp->px_chain->nodes);
  return ctx;
}

void proxy_chain_context_delete(struct proxy_chain_context *ctx) {
  if (ctx)
    free(ctx);
}

struct proxy_parser *proxy_parser_new(const char *proxychainstr) {
  struct proxy_parser *parser;

  parser = (struct proxy_parser *)safe_malloc(sizeof(struct proxy_parser));
  parser->done = 0;
  parser->value = NULL;

  parser->str = strdup(proxychainstr);

  parser->tokens = strtok_r(parser->str, ",", &parser->saveptr);
  if (parser->tokens) {
    parser->value = proxy_node_new(parser->tokens);
  } else {
    parser->done = 1;
  }

  return parser;
}

void proxy_parser_next(struct proxy_parser *parser) {

  parser->tokens = strtok_r(NULL, ",", &parser->saveptr);
  if (parser->tokens) {
    parser->value = proxy_node_new(parser->tokens);
  } else {
    parser->done = 1;
  }
}

void proxy_parser_delete(struct proxy_parser *parser) {
  if (parser) {
    free(parser->str);
    free(parser);
  }
}

/* XXX
 * This function is just an ugly PoC.
 *
 * A clean version should handle:
 *   - both v4 and v6 adresses
 *   - hostnames (how do we want to resolve them though??)
 *   - user:pass@ prefix before host specification
 */
static struct proxy_node *proxy_node_new(char *proxystr) {
  struct proxy_node *proxy;

  proxy = (struct proxy_node *)safe_zalloc(sizeof(struct proxy_node));

  if (strncasecmp(proxystr, "http://", 7) != 0) {
    fatal("Invalid protocol in proxy specification string: %s", proxystr);
  }

  proxy->px_type = PROXY_TYPE_HTTP;
  proxy_http_node_init(proxy, proxystr);

  return proxy;
}

static void proxy_node_delete(struct proxy_node *proxy) {
  if (proxy)
    free(proxy);
}

void forward_event(mspool *nsp, msevent *nse, void *udata) {
  enum nse_type cached_type;
  enum nse_status cached_status;
 
  cached_type = nse->type;
  cached_status = nse->status;
 
  nse->type = NSE_TYPE_CONNECT;
  nse->status = NSE_STATUS_SUCCESS;
 
  if (nsp->tracelevel > 0)
    nsock_trace(nsp, "Forwarding event upstream: SUCCESS TCP connect (IOD #%li) EID %li",
                nse->iod->id, nse->id);
 
  nse->iod->px_ctx->target_handler(nsp, nse, udata);
 
  nse->type = cached_type;
  nse->status = cached_status;
}

void nsock_proxy_ev_handler(nsock_pool nspool, nsock_event nsevent, void *udata) {
  msevent *nse = (msevent *)nsevent;
  struct proxy_node *current;

  if (nse->status != NSE_STATUS_SUCCESS)
    fatal("Error, but this is debug only!");

  current = PROXY_CTX_CURRENT(nse->iod->px_ctx);
  switch (current->px_type) {
    case PROXY_TYPE_HTTP:
      proxy_http_ev_handler(nspool, nsevent, udata);
      break;

    default:
      fatal("Invalid proxy type (%d)", current->px_type);
  }
}

void proxy_http_node_init(struct proxy_node *proxy, char *proxystr) {
  struct sockaddr_in *sin;
  char *strhost, *strport, *saveptr;

  strhost = strtok_r(proxystr + 7, ":", &saveptr);
  strport = strtok_r(NULL, ":", &saveptr);
  if (strport == NULL)
    strport = "8080";

  printf("init HTTP node http://%s:%s\n", strhost, strport);

  sin = (struct sockaddr_in *)&proxy->ss;
  sin->sin_family = AF_INET;
  inet_pton(AF_INET, strhost, &sin->sin_addr);

  proxy->sslen = sizeof(struct sockaddr_in);
  proxy->port = (unsigned short)atoi(strport);
}

void proxy_http_ev_handler(nsock_pool nspool, nsock_event nsevent, void *udata) {
  mspool *nsp = (mspool *)nspool;
  msevent *nse = (msevent *)nsevent;
  struct sockaddr_storage *ss;
  size_t sslen;
  unsigned short port;

  switch (nse->iod->px_ctx->px_state) {
    case PROXY_STATE_INITIAL:
      nse->iod->px_ctx->px_state = PROXY_STATE_HTTP_TCP_CONNECTED;

      if (PROXY_CTX_NEXT(nse->iod->px_ctx)) {
        struct proxy_node *next;

        next = PROXY_CTX_NEXT(nse->iod->px_ctx);
        ss = &next->ss;
        sslen = next->sslen;
        port = next->port;
      } else {
        ss = &nse->iod->px_ctx->target_ss;
        sslen = nse->iod->px_ctx->target_sslen;
        port = nse->iod->px_ctx->target_port;
      }
      nsock_printf(nspool, (nsock_iod)nse->iod, nsock_proxy_ev_handler,
                   4000, udata, "CONNECT %s:%d HTTP/1.1\r\n\r\n",
                   inet_ntop_ez(ss, sslen), (int)port);
      nsock_readlines(nspool, (nsock_iod)nse->iod, nsock_proxy_ev_handler, 4000, udata, 1);
      break;

    case PROXY_STATE_HTTP_TCP_CONNECTED:
      if (nse->type == NSE_TYPE_READ) {
        char *res;
        int reslen;

        res = nse_readbuf(nse, &reslen);

        /* TODO string check!! */
        if ((reslen >= 15) && strstr(res, "200 OK")) {
          nse->iod->px_ctx->px_state = PROXY_STATE_HTTP_TUNNEL_ESTABLISHED;
        }

        if (nse->iod->px_ctx->px_current->next == NULL) {
          forward_event(nsp, nse, udata);
        } else {
          nse->iod->px_ctx->px_current = nse->iod->px_ctx->px_current->next;
          nse->iod->px_ctx->px_state = PROXY_STATE_INITIAL;

          nsock_proxy_ev_handler(nsp, nse, udata);
        }
      }
      break;

    case PROXY_STATE_HTTP_TUNNEL_ESTABLISHED:
      forward_event(nsp, nse, udata);
      break;

    default:
      fatal("Invalid proxy state!");
  }
}

nsock_event_id proxy_http_connect_tcp(nsock_pool nsp, nsock_iod ms_iod, nsock_ev_handler handler,
                                      int timeout_msecs, void *userdata, struct sockaddr *saddr,
                                      size_t sslen, unsigned short port) {
  msiod *nsi = (msiod *)ms_iod;
  struct proxy_node *current;

  memcpy(&nsi->px_ctx->target_ss, saddr, sslen);
  nsi->px_ctx->target_sslen = sslen;
  nsi->px_ctx->target_port = port;
  nsi->px_ctx->target_handler = handler;

  current = PROXY_CTX_CURRENT(nsi->px_ctx);
  saddr = (struct sockaddr *)&current->ss;
  sslen = current->sslen;
  port  = current->port;
  handler = nsock_proxy_ev_handler;

  return nsock_connect_tcp_direct(nsp, ms_iod, handler, timeout_msecs, userdata, saddr, sslen, port);
}

char *proxy_http_data_encode(const char *src, size_t len, size_t *dlen) {
  // TODO
  return NULL;
}

char *proxy_http_data_decode(const char *src, size_t len, size_t *dlen) {
  // TODO
  return NULL;
}

