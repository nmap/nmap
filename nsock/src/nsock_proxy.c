/***************************************************************************
 * nsock_proxy.c -- This contains the functions relating to proxies.       *
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
#include <string.h>

#define IN_RANGE(x, min, max) ((x) >= (min) && (x) <= (max))

static struct proxy_node *proxy_node_new(const char *proxystr, const char *end);

/* --- Implemented proxy backends --- */
extern const struct proxy_spec ProxySpecHttp;
extern const struct proxy_spec ProxySpecSocks4;


static const struct proxy_spec *ProxyBackends[] = {
  &ProxySpecHttp,
  &ProxySpecSocks4,
  NULL
};


/* A proxy chain is a comma-separated list of proxy specification strings:
 * proto://[user:pass@]host[:port] */
int nsock_proxychain_new(const char *proxystr, nsock_proxychain *chain, nsock_pool nspool) {
  struct npool *nsp = (struct npool *)nspool;
  struct proxy_chain *pxc, **pchain = (struct proxy_chain **)chain;

  *pchain = NULL;

  pxc = (struct proxy_chain *)safe_malloc(sizeof(struct proxy_chain));
  gh_list_init(&pxc->nodes);

  if (proxystr) {
    const char *next = proxystr;
    const char *end = strchr(proxystr, ',');
    struct proxy_node *proxy;

    while (end != NULL) {
      proxy = proxy_node_new(next, end);
      if (!proxy)
        return -1;
      gh_list_append(&pxc->nodes, &proxy->nodeq);
      next = end + 1;
      end = strchr(next, ',');
    }
    proxy = proxy_node_new(next, strchr(next, '\0'));
    if (!proxy)
      return -1;
    gh_list_append(&pxc->nodes, &proxy->nodeq);
  }

  if (nsp) {
    if (nsock_pool_set_proxychain(nspool, pxc) < 0) {
      nsock_proxychain_delete(pxc);
      return -1;
    }
  }

  *pchain = pxc;
  return 1;
}

void nsock_proxychain_delete(nsock_proxychain chain) {
  struct proxy_chain *pchain = (struct proxy_chain *)chain;
  gh_lnode_t *lnode;

  if (!pchain)
    return;

  while ((lnode = gh_list_pop(&pchain->nodes)) != NULL) {
    struct proxy_node *node;

    node = container_of(lnode, struct proxy_node, nodeq);
    node->spec->ops->node_delete(node);
  }

  gh_list_free(&pchain->nodes);
  free(pchain);
}

int nsock_pool_set_proxychain(nsock_pool nspool, nsock_proxychain chain) {
  struct npool *nsp = (struct npool *)nspool;
  assert(nsp != NULL);

  if (nsp && nsp->px_chain) {
    nsock_log_error("Invalid call. Existing proxychain on this nsock_pool");
    return -1;
  }

  if (gh_list_count(&chain->nodes) < 1) {
    nsock_log_error("Invalid call. No proxies in chain");
    return -1;
  }

  nsp->px_chain = (struct proxy_chain *)chain;
  return 1;
}

struct proxy_chain_context *proxy_chain_context_new(nsock_pool nspool) {
  struct npool *nsp = (struct npool *)nspool;
  struct proxy_chain_context *ctx;

  ctx = (struct proxy_chain_context *)safe_malloc(sizeof(struct proxy_chain_context));
  ctx->px_chain = nsp->px_chain;
  ctx->px_state = PROXY_STATE_INITIAL;
  ctx->px_current = container_of(gh_list_first_elem(&nsp->px_chain->nodes),
                                 struct proxy_node,
                                 nodeq);
  return ctx;
}

void proxy_chain_context_delete(struct proxy_chain_context *ctx) {
  free(ctx);
}

static void uri_free(struct uri *uri) {
  free(uri->scheme);
  free(uri->user);
  free(uri->pass);
  free(uri->host);
  free(uri->path);
}

static int lowercase(char *s) {
  char *p;

  for (p = s; *p != '\0'; p++)
    *p = tolower((int) (unsigned char) *p);

  return p - s;
}

static int hex_digit_value(char digit) {
  static const char DIGITS[] = "0123456789abcdef";
  const char *p;

  if ((unsigned char)digit == '\0')
    return -1;

  p = strchr(DIGITS, tolower((int)(unsigned char)digit));
  if (p == NULL)
    return -1;

  return p - DIGITS;
}

static int percent_decode(char *s) {
  char *p, *q;

  /* Skip to the first '%'. If there are no percent escapes, this lets us
   * return without doing any copying. */
  q = s;
  while (*q != '\0' && *q != '%')
    q++;

  p = q;
  while (*q != '\0') {
    if (*q == '%') {
      int c, d;

      q++;
      c = hex_digit_value(*q);
      if (c == -1)
        return -1;
      q++;
      d = hex_digit_value(*q);
      if (d == -1)
        return -1;

      *p++ = c * 16 + d;
      q++;
      } else {
        *p++ = *q++;
      }
  }
  *p = '\0';

  return p - s;
}

static int uri_parse_authority(const char *authority, const char *end, struct uri *uri) {
  const char *portsep;
  const char *host_start, *host_end;
  const char *tail;

  /* We do not support "user:pass@" userinfo. The proxy has no use for it. */
  if (strchr_p(authority, end, '@') != NULL)
    return -1;

  /* Find the beginning and end of the host. */
  host_start = authority;

  if (*host_start == '[') {
    /* IPv6 address in brackets. */
    host_start++;
    if (host_start >= end ||
        NULL == (host_end = strchr_p(host_start, end, ']'))
       ) {
      nsock_log_error("Invalid IPv6 address: %s", authority);
      return -1;
    }

    portsep = host_end + 1;

  } else {
    for (portsep = end; portsep > host_start && *portsep != ':'; portsep--);

    if (portsep == host_start)
      portsep = end;
    host_end = portsep;
  }

  /* Get the port number. */
  if (portsep + 1 < end && *portsep == ':') {
    long n;

    errno = 0;
    n = parse_long(portsep + 1, &tail);
    if (errno || tail != end || !IN_RANGE(n, 1, 65535)) {
      nsock_log_error("Invalid port number (%ld), errno = %d", n, errno);
      return -1;
    }
    uri->port = n;
  } else {
    uri->port = -1;
  }

  /* Get the host. */
  uri->host = mkstr(host_start, host_end);
  if (percent_decode(uri->host) < 0) {
    nsock_log_error("Invalid URL encoding in host: %s", uri->host);
    free(uri->host);
    uri->host = NULL;
    return -1;
  }

  return 1;
}

static int parse_uri(const char *proxystr, const char *end, struct uri *uri) {
  const char *p, *q;

  /* Scheme, section 3.1. */
  p = proxystr;
  if (!isalpha(*p))
    goto fail;

  q = p;
  while (isalpha(*q) || isdigit(*q) || *q == '+' || *q == '-' || *q == '.') {
    q++;
    if (q >= end)
      goto fail;
  }

  if (*q != ':')
      goto fail;

  uri->scheme = mkstr(p, q);

  /* "An implementation should accept uppercase letters as equivalent to
   * lowercase in scheme names (e.g., allow "HTTP" as well as "http") for the
   * sake of robustness..." */
  lowercase(uri->scheme);

  /* Authority, section 3.2. */
  p = q + 1;
  if (p >= end)
    goto fail;
  if (p + 1 < end && *p == '/' && *(p + 1) == '/') {

    p += 2;
    q = p;
    while (q < end && !(*q == '/' || *q == '?' || *q == '#' || *q == '\0'))
      q++;

    if (uri_parse_authority(p, q, uri) < 0) {
      goto fail;
    }

    p = q;
  }

  /* Path, section 3.3. We include the query and fragment in the path. The
   * path is also not percent-decoded because we just pass it on to the origin
   * server. */

  uri->path = mkstr(p, end);

  return 1;

fail:
  uri_free(uri);
  return -1;
}

static struct proxy_node *proxy_node_new(const char *proxystr, const char *end) {
  int i;

  for (i = 0; ProxyBackends[i] != NULL; i++) {
    const struct proxy_spec *pspec;
    size_t prefix_len;

    pspec = ProxyBackends[i];
    prefix_len = strlen(pspec->prefix);
    if (end - proxystr > prefix_len && strncasecmp(proxystr, pspec->prefix, prefix_len) == 0) {
      struct proxy_node *proxy = NULL;
      struct uri uri;

      memset(&uri, 0x00, sizeof(struct uri));

      if (parse_uri(proxystr, end, &uri) < 0)
        break;

      if (pspec->ops->node_new(&proxy, &uri) < 0) {
        nsock_log_error("Cannot initialize proxy node %s", proxystr);
        uri_free(&uri);
        break;
      }

      uri_free(&uri);

      return proxy;
    }
  }
  nsock_log_error("Invalid protocol in proxy specification string: %s", proxystr);
  return NULL;
}

void forward_event(nsock_pool nspool, nsock_event nsevent, void *udata) {
  struct npool *nsp = (struct npool *)nspool;
  struct nevent *nse = (struct nevent *)nsevent;
  enum nse_type cached_type;
  enum nse_status cached_status;

  cached_type = nse->type;
  cached_status = nse->status;

  nse->type = nse->iod->px_ctx->target_ev_type;

  if (nse->status != NSE_STATUS_SUCCESS)
    nse->status = NSE_STATUS_PROXYERROR;

  nsock_log_info("Forwarding event upstream: TCP connect %s (IOD #%li) EID %li",
                 nse_status2str(nse->status), nse->iod->id, nse->id);

  nse->iod->px_ctx->target_handler(nsp, nse, udata);

  nse->type = cached_type;
  nse->status = cached_status;
}

void nsock_proxy_ev_dispatch(nsock_pool nspool, nsock_event nsevent, void *udata) {
  struct nevent *nse = (struct nevent *)nsevent;

  if (nse->status == NSE_STATUS_SUCCESS) {
    struct proxy_node *current;

    current = nse->iod->px_ctx->px_current;
    assert(current);
    current->spec->ops->handler(nspool, nsevent, udata);
  } else {
    forward_event(nspool, nsevent, udata);
  }
}

int proxy_resolve(const char *host, struct sockaddr *addr, size_t *addrlen, int ai_family) {
  struct addrinfo hints;
  struct addrinfo *res;
  int rc;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = ai_family;
  /* All proxy types are TCP-only at the moment */
  hints.ai_socktype = SOCK_STREAM;

  rc = getaddrinfo(host, NULL, &hints, &res);
  if (rc) {
    nsock_log_info("getaddrinfo error: %s", gai_strerror(rc));
    return -abs(rc);
  }

  *addr = *res->ai_addr;
  *addrlen = res->ai_addrlen;
  freeaddrinfo(res);
  return 1;
}

