/*
 * ndisc.c
 *
 * Kernel arp/ndisc table operations.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 */

#ifndef DNET_NDISC_H
#define DNET_NDISC_H

/*
 * NDISC cache entry
 */
struct ndisc_entry {
    int    intf_index;
	struct addr	ndisc_pa;			/* protocol address */
	struct addr	ndisc_ha;			/* hardware address */
};

typedef struct ndisc_handle ndisc_t;

typedef int (*ndisc_handler)(const struct ndisc_entry *entry, void *arg);

__BEGIN_DECLS
ndisc_t	*ndisc_open(void);
int	 ndisc_add(ndisc_t *n, const struct ndisc_entry *entry);
int	 ndisc_delete(ndisc_t *n, const struct ndisc_entry *entry);
int	 ndisc_get(ndisc_t *n, struct ndisc_entry *entry);
int	 ndisc_loop(ndisc_t *n, ndisc_handler callback, void *arg);
ndisc_t	*ndisc_close(ndisc_t *r);
__END_DECLS

#endif /* DNET_NDISC_H */
