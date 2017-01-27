/*
 * fw-none.c
 * 
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: fw-none.c 208 2002-01-20 21:23:28Z dugsong $
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "dnet.h"

fw_t *
fw_open(void)
{
	errno = ENOSYS;
	return (NULL);
}

int
fw_add(fw_t *f, const struct fw_rule *rule)
{
	errno = ENOSYS;
	return (-1);
}

int
fw_delete(fw_t *f, const struct fw_rule *rule)
{
	errno = ENOSYS;
	return (-1);
}

int
fw_loop(fw_t *f, fw_handler callback, void *arg)
{
	errno = ENOSYS;
	return (-1);
}

fw_t *
fw_close(fw_t *f)
{
	return (NULL);
}
