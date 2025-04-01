/*
 * tun.h
 *
 * Network tunnel device.
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_TUN_H
#define DNET_TUN_H

typedef struct tun	tun_t;

__BEGIN_DECLS
tun_t	   *tun_open(struct addr *src, struct addr *dst, int mtu);
int	    tun_fileno(tun_t *tun);
const char *tun_name(tun_t *tun);
ssize_t	    tun_send(tun_t *tun, const void *buf, size_t size);
ssize_t	    tun_recv(tun_t *tun, void *buf, size_t size);
tun_t	   *tun_close(tun_t *tun);
__END_DECLS

#endif /* DNET_TUN_H */
