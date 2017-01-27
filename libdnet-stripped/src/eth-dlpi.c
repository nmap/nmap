/*
 * eth-dlpi.c
 *
 * Based on Neal Nuckolls' 1992 "How to Use DLPI" paper.
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: eth-dlpi.c 560 2005-02-10 16:48:36Z dugsong $
 */

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_SYS_BUFMOD_H
#include <sys/bufmod.h>
#endif
#ifdef HAVE_SYS_DLPI_H
#include <sys/dlpi.h>
#elif defined(HAVE_SYS_DLPIHDR_H)
#include <sys/dlpihdr.h>
#endif
#ifdef HAVE_SYS_DLPI_EXT_H
#include <sys/dlpi_ext.h>
#endif
#include <sys/stream.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>

#include "dnet.h"

#ifndef INFTIM
#define INFTIM	-1
#endif

struct eth_handle {
	int	fd;
	int	sap_len;
};

static int
dlpi_msg(int fd, union DL_primitives *dlp, int rlen, int flags,
    int ack, int alen, int size)
{
	struct strbuf ctl;

	ctl.maxlen = 0;
	ctl.len = rlen;
	ctl.buf = (caddr_t)dlp;
	
	if (putmsg(fd, &ctl, NULL, flags) < 0)
		return (-1);
	
	ctl.maxlen = size;
	ctl.len = 0;
	
	flags = 0;

	if (getmsg(fd, &ctl, NULL, &flags) < 0)
		return (-1);
	
	if (dlp->dl_primitive != ack || ctl.len < alen)
		return (-1);
	
	return (0);
}

#if defined(DLIOCRAW) || defined(HAVE_SYS_DLPIHDR_H)
static int
strioctl(int fd, int cmd, int len, char *dp)
{
	struct strioctl str;
	
	str.ic_cmd = cmd;
	str.ic_timout = INFTIM;
	str.ic_len = len;
	str.ic_dp = dp;
	
	if (ioctl(fd, I_STR, &str) < 0)
		return (-1);
	
	return (str.ic_len);
}
#endif

#ifdef HAVE_SYS_DLPIHDR_H
/* XXX - OSF1 is nuts */
#define ND_GET	('N' << 8 + 0)

static int
eth_match_ppa(eth_t *e, const char *device)
{
	char *p, dev[16], buf[256];
	int len, ppa;

	strlcpy(buf, "dl_ifnames", sizeof(buf));
	
	if ((len = strioctl(e->fd, ND_GET, sizeof(buf), buf)) < 0)
		return (-1);
	
	for (p = buf; p < buf + len; p += strlen(p) + 1) {
		ppa = -1;
		if (sscanf(p, "%s (PPA %d)\n", dev, &ppa) != 2)
			break;
		if (strcmp(dev, device) == 0)
			break;
	}
	return (ppa);
}
#else
static char *
dev_find_ppa(char *dev)
{
	char *p;

	p = dev + strlen(dev);
	while (p > dev && strchr("0123456789", *(p - 1)) != NULL)
		p--;
	if (*p == '\0')
		return NULL;

	return p;
}
#endif

eth_t *
eth_open(const char *device)
{
	union DL_primitives *dlp;
	uint32_t buf[8192];
	char *p, dev[16];
	eth_t *e;
	int ppa;

	if ((e = calloc(1, sizeof(*e))) == NULL)
		return (NULL);

#ifdef HAVE_SYS_DLPIHDR_H
	if ((e->fd = open("/dev/streams/dlb", O_RDWR)) < 0)
		return (eth_close(e));
	
	if ((ppa = eth_match_ppa(e, device)) < 0) {
		errno = ESRCH;
		return (eth_close(e));
	}
#else
	e->fd = -1;
	snprintf(dev, sizeof(dev), "/dev/%s", device);
	if ((p = dev_find_ppa(dev)) == NULL) {
		errno = EINVAL;
		return (eth_close(e));
	}
	ppa = atoi(p);
	*p = '\0';

	if ((e->fd = open(dev, O_RDWR)) < 0) {
		snprintf(dev, sizeof(dev), "/dev/%s", device);
		if ((e->fd = open(dev, O_RDWR)) < 0) {
			snprintf(dev, sizeof(dev), "/dev/net/%s", device);
			if ((e->fd = open(dev, O_RDWR)) < 0)
				return (eth_close(e));
		}
	}
#endif
	dlp = (union DL_primitives *)buf;
	dlp->info_req.dl_primitive = DL_INFO_REQ;
	
	if (dlpi_msg(e->fd, dlp, DL_INFO_REQ_SIZE, RS_HIPRI,
	    DL_INFO_ACK, DL_INFO_ACK_SIZE, sizeof(buf)) < 0)
		return (eth_close(e));
	
	e->sap_len = dlp->info_ack.dl_sap_length;
	
	if (dlp->info_ack.dl_provider_style == DL_STYLE2) {
		dlp->attach_req.dl_primitive = DL_ATTACH_REQ;
		dlp->attach_req.dl_ppa = ppa;
		
		if (dlpi_msg(e->fd, dlp, DL_ATTACH_REQ_SIZE, 0,
		    DL_OK_ACK, DL_OK_ACK_SIZE, sizeof(buf)) < 0)
			return (eth_close(e));
	}
	memset(&dlp->bind_req, 0, DL_BIND_REQ_SIZE);
	dlp->bind_req.dl_primitive = DL_BIND_REQ;
#ifdef DL_HP_RAWDLS
	dlp->bind_req.dl_sap = 24;	/* from HP-UX DLPI programmers guide */
	dlp->bind_req.dl_service_mode = DL_HP_RAWDLS;
#else
	dlp->bind_req.dl_sap = DL_ETHER;
	dlp->bind_req.dl_service_mode = DL_CLDLS;
#endif
	if (dlpi_msg(e->fd, dlp, DL_BIND_REQ_SIZE, 0,
	    DL_BIND_ACK, DL_BIND_ACK_SIZE, sizeof(buf)) < 0)
		return (eth_close(e));
#ifdef DLIOCRAW
	if (strioctl(e->fd, DLIOCRAW, 0, NULL) < 0)
		return (eth_close(e));
#endif
	return (e);
}

ssize_t
eth_send(eth_t *e, const void *buf, size_t len)
{
#if defined(DLIOCRAW)
	return (write(e->fd, buf, len));
#else
	union DL_primitives *dlp;
	struct strbuf ctl, data;
	struct eth_hdr *eth;
	uint32_t ctlbuf[8192];
	u_char sap[4] = { 0, 0, 0, 0 };
	int dlen;

	dlp = (union DL_primitives *)ctlbuf;
#ifdef DL_HP_RAWDATA_REQ
	dlp->dl_primitive = DL_HP_RAWDATA_REQ;
	dlen = DL_HP_RAWDATA_REQ_SIZE;
#else
	dlp->unitdata_req.dl_primitive = DL_UNITDATA_REQ;
	dlp->unitdata_req.dl_dest_addr_length = ETH_ADDR_LEN;
	dlp->unitdata_req.dl_dest_addr_offset = DL_UNITDATA_REQ_SIZE;
	dlp->unitdata_req.dl_priority.dl_min =
	    dlp->unitdata_req.dl_priority.dl_max = 0;
	dlen = DL_UNITDATA_REQ_SIZE;
#endif
	eth = (struct eth_hdr *)buf;
	*(uint16_t *)sap = ntohs(eth->eth_type);
	
	/* XXX - DLSAP setup logic from ISC DHCP */
	ctl.maxlen = 0;
	ctl.len = dlen + ETH_ADDR_LEN + abs(e->sap_len);
	ctl.buf = (char *)ctlbuf;
	
	if (e->sap_len >= 0) {
		memcpy(ctlbuf + dlen, sap, e->sap_len);
		memcpy(ctlbuf + dlen + e->sap_len,
		    eth->eth_dst.data, ETH_ADDR_LEN);
	} else {
		memcpy(ctlbuf + dlen, eth->eth_dst.data, ETH_ADDR_LEN);
		memcpy(ctlbuf + dlen + ETH_ADDR_LEN, sap, abs(e->sap_len));
	}
	data.maxlen = 0;
	data.len = len;
	data.buf = (char *)buf;

	if (putmsg(e->fd, &ctl, &data, 0) < 0)
		return (-1);

	return (len);
#endif
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
	union DL_primitives *dlp;
	u_char buf[2048];
	
	dlp = (union DL_primitives *)buf;
	dlp->physaddr_req.dl_primitive = DL_PHYS_ADDR_REQ;
	dlp->physaddr_req.dl_addr_type = DL_CURR_PHYS_ADDR;

	if (dlpi_msg(e->fd, dlp, DL_PHYS_ADDR_REQ_SIZE, 0,
	    DL_PHYS_ADDR_ACK, DL_PHYS_ADDR_ACK_SIZE, sizeof(buf)) < 0)
		return (-1);

	memcpy(ea, buf + dlp->physaddr_ack.dl_addr_offset, sizeof(*ea));
	
	return (0);
}

int
eth_set(eth_t *e, const eth_addr_t *ea)
{
	union DL_primitives *dlp;
	u_char buf[2048];

	dlp = (union DL_primitives *)buf;
	dlp->set_physaddr_req.dl_primitive = DL_SET_PHYS_ADDR_REQ;
	dlp->set_physaddr_req.dl_addr_length = ETH_ADDR_LEN;
	dlp->set_physaddr_req.dl_addr_offset = DL_SET_PHYS_ADDR_REQ_SIZE;

	memcpy(buf + DL_SET_PHYS_ADDR_REQ_SIZE, ea, sizeof(*ea));
	
	return (dlpi_msg(e->fd, dlp, DL_SET_PHYS_ADDR_REQ_SIZE + ETH_ADDR_LEN,
	    0, DL_OK_ACK, DL_OK_ACK_SIZE, sizeof(buf)));
}
