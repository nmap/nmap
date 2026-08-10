/*
 * route.c
 *
 * Kernel route table operations.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_ROUTE_H
#define DNET_ROUTE_H

/*
 * Routing table entry
 */
struct route_entry {
	char		intf_name[INTF_NAME_LEN];	/* interface name */
	struct addr	route_dst;	/* destination address */
	struct addr	route_gw;	/* gateway address */
	int		metric;		/* per-route metric */
};

typedef struct route_handle route_t;

typedef int (*route_handler)(const struct route_entry *entry, void *arg);

__BEGIN_DECLS
route_t	*route_open(void);
int	 route_add(route_t *r, const struct route_entry *entry);
int	 route_add_dev(route_t *r, const struct route_entry *entry, const char* dev);
int	 route6_add(route_t *r, const struct route_entry *entry, int intf_index);
int	 route_delete(route_t *r, const struct route_entry *entry);
int	 route6_delete(route_t *r, const struct route_entry *entry, int intf_index);
int	 route_get(route_t *r, struct route_entry *entry);
int	 route_loop(route_t *r, route_handler callback, void *arg);
route_t	*route_close(route_t *r);
__END_DECLS

#endif /* DNET_ROUTE_H */
