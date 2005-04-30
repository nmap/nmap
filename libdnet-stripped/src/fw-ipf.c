
/*
 * fw-ipf.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: fw-ipf.c,v 1.18 2005/02/16 21:42:53 dugsong Exp $
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#define _NETINET_IP6_H_		/* XXX */
#include <netinet/in.h>
#define ip_t	ipf_ip_t
#ifdef HAVE_NETINET_IP_FIL_COMPAT_H
# include <netinet/ip_fil_compat.h>
#else
# include <netinet/ip_compat.h>
#endif
#include <netinet/ip_fil.h>
#undef ip_t

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KMEM_NAME	"/dev/kmem"

#include "dnet.h"

#if !defined(fi_saddr) && !defined(fi_daddr)
# define fi_saddr	fi_src.s_addr
# define fi_daddr	fi_dst.s_addr
#endif

struct fw_handle {
	int	fd;
	int	kfd;
};

static void
rule_to_ipf(const struct fw_rule *rule, struct frentry *fr)
{
	memset(fr, 0, sizeof(*fr));

	if (*rule->fw_device != '\0') {
		strlcpy(fr->fr_ifname, rule->fw_device, IFNAMSIZ);
		strlcpy(fr->fr_oifname, rule->fw_device, IFNAMSIZ);
	}
	if (rule->fw_op == FW_OP_ALLOW)
		fr->fr_flags |= FR_PASS;
	else
		fr->fr_flags |= FR_BLOCK;

	if (rule->fw_dir == FW_DIR_IN)
		fr->fr_flags |= FR_INQUE;
	else
		fr->fr_flags |= FR_OUTQUE;
	
	fr->fr_ip.fi_p = rule->fw_proto;
	fr->fr_ip.fi_saddr = rule->fw_src.addr_ip;
	fr->fr_ip.fi_daddr = rule->fw_dst.addr_ip;
	addr_btom(rule->fw_src.addr_bits, &fr->fr_mip.fi_saddr, IP_ADDR_LEN);
	addr_btom(rule->fw_dst.addr_bits, &fr->fr_mip.fi_daddr, IP_ADDR_LEN);
	
	switch (rule->fw_proto) {
	case IPPROTO_ICMP:
		fr->fr_icmpm = rule->fw_sport[1] << 8 |
		    (rule->fw_dport[1] & 0xff);
		fr->fr_icmp = rule->fw_sport[0] << 8 |
		    (rule->fw_dport[0] & 0xff);
		break;
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		fr->fr_sport = rule->fw_sport[0];
		if (rule->fw_sport[0] != rule->fw_sport[1]) {
			fr->fr_scmp = FR_INRANGE;
			fr->fr_stop = rule->fw_sport[1];
		} else
			fr->fr_scmp = FR_EQUAL;

		fr->fr_dport = rule->fw_dport[0];
		if (rule->fw_dport[0] != rule->fw_dport[1]) {
			fr->fr_dcmp = FR_INRANGE;
			fr->fr_dtop = rule->fw_dport[1];
		} else
			fr->fr_dcmp = FR_EQUAL;
		break;
	}
}

static void
ipf_ports_to_rule(uint8_t cmp, uint16_t port, uint16_t top, uint16_t *range)
{
	switch (cmp) {
	case FR_EQUAL:
		range[0] = range[1] = port;
		break;
	case FR_NEQUAL:
		range[0] = port - 1;
		range[1] = port + 1;
		break;
	case FR_LESST:
		range[0] = 0;
		range[1] = port - 1;
		break;
	case FR_GREATERT:
		range[0] = port + 1;
		range[1] = TCP_PORT_MAX;
		break;
	case FR_LESSTE:
		range[0] = 0;
		range[1] = port;
		break;
	case FR_GREATERTE:
		range[0] = port;
		range[1] = TCP_PORT_MAX;
		break;
	case FR_OUTRANGE:
		range[0] = port;
		range[1] = top;
		break;
	case FR_INRANGE:
		range[0] = port;
		range[1] = top;
		break;
	default:
		range[0] = 0;
		range[1] = TCP_PORT_MAX;
	}
}

static void
ipf_to_rule(const struct frentry *fr, struct fw_rule *rule)
{
	memset(rule, 0, sizeof(*rule));

	strlcpy(rule->fw_device, fr->fr_ifname, sizeof(rule->fw_device));
	rule->fw_op = (fr->fr_flags & FR_PASS) ? FW_OP_ALLOW : FW_OP_BLOCK;
	rule->fw_dir = (fr->fr_flags & FR_INQUE) ? FW_DIR_IN : FW_DIR_OUT;
	rule->fw_proto = fr->fr_ip.fi_p;

	rule->fw_src.addr_type = rule->fw_dst.addr_type = ADDR_TYPE_IP;
	rule->fw_src.addr_ip = fr->fr_ip.fi_saddr;
	rule->fw_dst.addr_ip = fr->fr_ip.fi_daddr;
	addr_mtob(&fr->fr_mip.fi_saddr, IP_ADDR_LEN,
	    &rule->fw_src.addr_bits);
	addr_mtob(&fr->fr_mip.fi_daddr, IP_ADDR_LEN,
	    &rule->fw_dst.addr_bits);
	
	switch (rule->fw_proto) {
	case IPPROTO_ICMP:
		rule->fw_sport[0] = ntohs(fr->fr_icmp & fr->fr_icmpm) >> 8;
		rule->fw_sport[1] = ntohs(fr->fr_icmpm) >> 8;
		rule->fw_dport[0] = ntohs(fr->fr_icmp & fr->fr_icmpm) & 0xff;
		rule->fw_dport[1] = ntohs(fr->fr_icmpm) & 0xff;
		break;
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		ipf_ports_to_rule(fr->fr_scmp, fr->fr_sport,
		    fr->fr_stop, rule->fw_sport);
		ipf_ports_to_rule(fr->fr_dcmp, fr->fr_dport,
		    fr->fr_dtop, rule->fw_dport);
		break;
	}
}

fw_t *
fw_open(void)
{
	fw_t *fw;
	
	if ((fw = calloc(1, sizeof(*fw))) != NULL) {
		fw->fd = fw->kfd = -1;
		if ((fw->fd = open(IPL_NAME, O_RDWR, 0)) < 0)
			return (fw_close(fw));
		if ((fw->kfd = open(KMEM_NAME, O_RDONLY)) < 0)
			return (fw_close(fw));
	}
	return (fw);
}

int
fw_add(fw_t *fw, const struct fw_rule *rule)
{
	struct frentry fr;
	
	assert(fw != NULL && rule != NULL);
	
	rule_to_ipf(rule, &fr);
	
	return (ioctl(fw->fd, SIOCADDFR, &fr));
}

int
fw_delete(fw_t *fw, const struct fw_rule *rule)
{
	struct frentry fr;
	
	assert(fw != NULL && rule != NULL);

	rule_to_ipf(rule, &fr);
	
	return (ioctl(fw->fd, SIOCDELFR, &fr));
}

static int
fw_kcopy(fw_t *fw, u_char *buf, off_t pos, size_t n)
{
	int i;
	
	if (lseek(fw->kfd, pos, 0) < 0)
		return (-1);

	while ((i = read(fw->kfd, buf, n)) < n) {
		if (i <= 0)
			return (-1);
		buf += i;
		n -= i;
	}
	return (0);
}

int
fw_loop(fw_t *fw, fw_handler callback, void *arg)
{
	struct friostat fio;
	struct friostat *fiop = &fio;
	struct frentry *frp, fr;
	struct fw_rule rule;
	int ret;
	
	memset(&fio, 0, sizeof(fio));
#ifdef __OpenBSD__
	if (ioctl(fw->fd, SIOCGETFS, fiop) < 0)
#else
	if (ioctl(fw->fd, SIOCGETFS, &fiop) < 0)	/* XXX - darren! */
#endif
		return (-1);

	for (frp = fio.f_fout[(int)fio.f_active]; frp != NULL;
	    frp = fr.fr_next) {
		if (fw_kcopy(fw, (u_char *)&fr, (u_long)frp, sizeof(fr)) < 0)
			return (-1);
		ipf_to_rule(&fr, &rule);
		if ((ret = callback(&rule, arg)) != 0)
			return (ret);
	}
	for (frp = fio.f_fin[(int)fio.f_active]; frp != NULL;
	    frp = fr.fr_next) {
		if (fw_kcopy(fw, (u_char *)&fr, (u_long)frp, sizeof(fr)) < 0)
			return (-1);
		ipf_to_rule(&fr, &rule);
		if ((ret = callback(&rule, arg)) != 0)
			return (ret);
	}
	return (0);
}

fw_t *
fw_close(fw_t *fw)
{
	if (fw != NULL) {
		if (fw->fd >= 0)
			close(fw->fd);
		if (fw->kfd >= 0)
			close(fw->kfd);
		free(fw);
	}
	return (NULL);
}
