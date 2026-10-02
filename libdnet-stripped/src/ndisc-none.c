/*
 * ndisc-linux.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "dnet.h"

ndisc_t *
ndisc_open(void)
{
	errno = ENOSYS;
	return (NULL);
}

int
ndisc_add(ndisc_t *n, const struct ndisc_entry *entry)
{
	errno = ENOSYS;
	return (-1);
}

int
ndisc_delete(ndisc_t *n, const struct ndisc_entry *entry)
{
	errno = ENOSYS;
	return (-1);
}

int
ndisc_get(ndisc_t *n, struct ndisc_entry *entry)
{
	errno = ENOSYS;
	return (-1);
}

int
ndisc_loop(ndisc_t *n, ndisc_handler callback, void *arg)
{
	errno = ENOSYS;
	return (-1);
}

ndisc_t *
ndisc_close(ndisc_t *n)
{
	return (NULL);
}
