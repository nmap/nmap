/*
 * eth-ndd.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: eth-ndd.c 547 2005-01-25 21:30:40Z dugsong $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ndd_var.h>
#include <sys/kinfo.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct eth_handle {
	char	device[16];
	int	fd;
};

eth_t *
eth_open(const char *device)
{
	struct sockaddr_ndd_8022 sa;
	eth_t *e;
	
	if ((e = calloc(1, sizeof(*e))) == NULL)
		return (NULL);

	if ((e->fd = socket(AF_NDD, SOCK_DGRAM, NDD_PROT_ETHER)) < 0)
		return (eth_close(e));
	
	sa.sndd_8022_family = AF_NDD;
        sa.sndd_8022_len = sizeof(sa);
	sa.sndd_8022_filtertype = NS_ETHERTYPE;
	sa.sndd_8022_ethertype = 0;
	sa.sndd_8022_filterlen = sizeof(struct ns_8022);
	strlcpy(sa.sndd_8022_nddname, device, sizeof(sa.sndd_8022_nddname));
	
	if (bind(e->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return (eth_close(e));
	
	if (connect(e->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return (eth_close(e));
	
	/* XXX - SO_BROADCAST needed? */
	
	return (e);
}

ssize_t
eth_send(eth_t *e, const void *buf, size_t len)
{
	return (write(e->fd, buf, len));
}

eth_t *
eth_close(eth_t *e)
{
	if (e != NULL) {
		if (e->fd >= 0)
			close(e->fd);
		free(e);
	}
	return (NULL);
}

int
eth_get(eth_t *e, eth_addr_t *ea)
{
	struct kinfo_ndd *nddp;
	int size;
	void *end;
	
	if ((size = getkerninfo(KINFO_NDD, 0, 0, 0)) == 0) {
		errno = ENOENT;
		return (-1);
	} else if (size < 0)
		return (-1);
	
	if ((nddp = malloc(size)) == NULL)
		return (-1);
                     
	if (getkerninfo(KINFO_NDD, nddp, &size, 0) < 0) {
		free(nddp);
		return (-1);
	}
	for (end = (void *)nddp + size; (void *)nddp < end; nddp++) {
		if (strcmp(nddp->ndd_alias, e->device) == 0 ||
		    strcmp(nddp->ndd_name, e->device) == 0) {
			memcpy(ea, nddp->ndd_addr, sizeof(*ea));
		}
	}
	free(nddp);
	
	if ((void *)nddp >= end) {
		errno = ESRCH;
		return (-1);
	}
	return (0);
}

int
eth_set(eth_t *e, const eth_addr_t *ea)
{
	errno = ENOSYS;
	return (-1);
}
