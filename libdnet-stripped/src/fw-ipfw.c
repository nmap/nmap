/*
 * fw-ipfw.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: fw-ipfw.c,v 1.16 2004/01/14 04:52:10 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct fw_handle {
	int	fd;
};

static void
fr_to_ipfw_device(const char *device, char *name, short *unit)
{
	char *p;

	p = strpbrk(device, "0123456789");
	*unit = atoi(p);
	strlcpy(name, device, p - device + 1);
}

static void
fr_to_ipfw(const struct fw_rule *fr, struct ip_fw *ipfw)
{
	int i;
	
	memset(ipfw, 0, sizeof(*ipfw));

	if (fr->fw_dir == FW_DIR_IN) {
		if (*fr->fw_device != '\0') {
			fr_to_ipfw_device(fr->fw_device,
			    ipfw->fw_in_if.fu_via_if.name,
			    &ipfw->fw_in_if.fu_via_if.unit);
			ipfw->fw_flg |= IP_FW_F_IIFNAME;
		}
		ipfw->fw_flg |= IP_FW_F_IN;
	} else {
		if (*fr->fw_device != '\0') {
			fr_to_ipfw_device(fr->fw_device,
			    ipfw->fw_out_if.fu_via_if.name,
			    &ipfw->fw_out_if.fu_via_if.unit);
			ipfw->fw_flg |= IP_FW_F_OIFNAME;
		}
		ipfw->fw_flg |= IP_FW_F_OUT;
	}
	if (fr->fw_op == FW_OP_ALLOW)
		ipfw->fw_flg |= IP_FW_F_ACCEPT;
	else
		ipfw->fw_flg |= IP_FW_F_DENY;
	
	ipfw->fw_prot = fr->fw_proto;
	ipfw->fw_src.s_addr = fr->fw_src.addr_ip;
	ipfw->fw_dst.s_addr = fr->fw_dst.addr_ip;
	addr_btom(fr->fw_src.addr_bits, &ipfw->fw_smsk.s_addr, IP_ADDR_LEN);
	addr_btom(fr->fw_dst.addr_bits, &ipfw->fw_dmsk.s_addr, IP_ADDR_LEN);

	switch (fr->fw_proto) {
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		i = 0;
		if (fr->fw_sport[0] != fr->fw_sport[1]) {
			ipfw->fw_flg |= IP_FW_F_SRNG;
			ipfw->fw_uar.fw_pts[i++] = fr->fw_sport[0];
			ipfw->fw_uar.fw_pts[i++] = fr->fw_sport[1];
			IP_FW_SETNSRCP(ipfw, 2);
		} else if (fr->fw_sport[0] > 0) {
			ipfw->fw_uar.fw_pts[i++] = fr->fw_sport[0];
			IP_FW_SETNSRCP(ipfw, 1);
		}
		if (fr->fw_dport[0] != fr->fw_dport[1]) {
			ipfw->fw_flg |= IP_FW_F_DRNG;
			ipfw->fw_uar.fw_pts[i++] = fr->fw_dport[0];
			ipfw->fw_uar.fw_pts[i++] = fr->fw_dport[1];
			IP_FW_SETNDSTP(ipfw, 2);
		} else if (fr->fw_dport[0] > 0) {
			ipfw->fw_uar.fw_pts[i++] = fr->fw_dport[0];
			IP_FW_SETNDSTP(ipfw, 1);
		}
		break;
	case IP_PROTO_ICMP:
		if (fr->fw_sport[1]) {
			ipfw->fw_uar.fw_icmptypes[fr->fw_sport[0] / 32] |=
			    1 << (fr->fw_sport[0] % 32);
			ipfw->fw_flg |= IP_FW_F_ICMPBIT;
		}
		/* XXX - no support for ICMP code. */
	  	break;
	}
}

static void
ipfw_to_fr(const struct ip_fw *ipfw, struct fw_rule *fr)
{
	int i;
	
	memset(fr, 0, sizeof(*fr));

	if ((ipfw->fw_flg & IP_FW_F_IN) && *ipfw->fw_in_if.fu_via_if.name)
		snprintf(fr->fw_device, sizeof(fr->fw_device), "%s%d",
		    ipfw->fw_in_if.fu_via_if.name,
		    ipfw->fw_in_if.fu_via_if.unit);
	else if ((ipfw->fw_flg & IP_FW_F_OUT) &&
	    *ipfw->fw_out_if.fu_via_if.name)
		snprintf(fr->fw_device, sizeof(fr->fw_device), "%s%d",
		    ipfw->fw_out_if.fu_via_if.name,
		    ipfw->fw_out_if.fu_via_if.unit);
	
	fr->fw_op = (ipfw->fw_flg & IP_FW_F_ACCEPT) ?
	    FW_OP_ALLOW : FW_OP_BLOCK;
	fr->fw_dir = (ipfw->fw_flg & IP_FW_F_IN) ? FW_DIR_IN : FW_DIR_OUT;
	fr->fw_proto = ipfw->fw_prot;

	fr->fw_src.addr_type = fr->fw_dst.addr_type = ADDR_TYPE_IP;
	fr->fw_src.addr_ip = ipfw->fw_src.s_addr;
	fr->fw_dst.addr_ip = ipfw->fw_dst.s_addr;
	addr_mtob(&ipfw->fw_smsk.s_addr, IP_ADDR_LEN, &fr->fw_src.addr_bits);
	addr_mtob(&ipfw->fw_dmsk.s_addr, IP_ADDR_LEN, &fr->fw_dst.addr_bits);

	switch (fr->fw_proto) {
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		if ((ipfw->fw_flg & IP_FW_F_SRNG) &&
		    IP_FW_GETNSRCP(ipfw) == 2) {
			fr->fw_sport[0] = ipfw->fw_uar.fw_pts[0];
			fr->fw_sport[1] = ipfw->fw_uar.fw_pts[1];
		} else if (IP_FW_GETNSRCP(ipfw) == 1) {
			fr->fw_sport[0] = fr->fw_sport[1] =
			    ipfw->fw_uar.fw_pts[0];
		} else if (IP_FW_GETNSRCP(ipfw) == 0) {
		  	fr->fw_sport[0] = 0;
			fr->fw_sport[1] = TCP_PORT_MAX;
		}
		
		if ((ipfw->fw_flg & IP_FW_F_DRNG) &&
		    IP_FW_GETNDSTP(ipfw) == 2) {
			i = IP_FW_GETNSRCP(ipfw);
			fr->fw_dport[0] = ipfw->fw_uar.fw_pts[i];
			fr->fw_dport[1] = ipfw->fw_uar.fw_pts[i + 1];
		} else if (IP_FW_GETNDSTP(ipfw) == 1) {
			i = IP_FW_GETNSRCP(ipfw);
			fr->fw_dport[0] = fr->fw_dport[1] =
			    ipfw->fw_uar.fw_pts[i];
		} else if (IP_FW_GETNDSTP(ipfw) == 0) {
		  	fr->fw_dport[0] = 0;
			fr->fw_dport[1] = TCP_PORT_MAX;
		}
		break;
	case IP_PROTO_ICMP:
		if (ipfw->fw_flg & IP_FW_F_ICMPBIT) {
			for (i = 0; i < IP_FW_ICMPTYPES_DIM * 32; i++) {
				if (ipfw->fw_uar.fw_icmptypes[i / 32] &
				    (1U << (i % 32))) {
					fr->fw_sport[0] = i;
					fr->fw_sport[1] = 0xff;
					break;
				}
			}
		}
	  	/* XXX - no support for ICMP code. */
	  	break;
	}
}

fw_t *
fw_open(void)
{
	fw_t *fw;
	
	if ((fw = calloc(1, sizeof(*fw))) != NULL) {
		if ((fw->fd = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) < 0)
			return (fw_close(fw));
	}
	return (fw);
}

int
fw_add(fw_t *fw, const struct fw_rule *rule)
{
	struct ip_fw ipfw;
	
	assert(fw != NULL && rule != NULL);

	fr_to_ipfw(rule, &ipfw);

	return (setsockopt(fw->fd, IPPROTO_IP, IP_FW_ADD,
	    &ipfw, sizeof(ipfw)));
}

static int
fw_cmp(const struct fw_rule *a, const struct fw_rule *b)
{
	if (strcmp(a->fw_device, b->fw_device) != 0 || a->fw_op != b->fw_op ||
	    a->fw_dir != b->fw_dir || a->fw_proto != b->fw_proto || 
	    addr_cmp(&a->fw_src, &b->fw_src) != 0 ||
	    addr_cmp(&a->fw_dst, &b->fw_dst) != 0 ||
	    memcmp(a->fw_sport, b->fw_sport, sizeof(a->fw_sport)) != 0 ||
	    memcmp(a->fw_dport, b->fw_dport, sizeof(a->fw_dport)) != 0)
		return (-1);
	return (0);
}

int
fw_delete(fw_t *fw, const struct fw_rule *rule)
{
	struct ip_fw *ipfw;
	struct fw_rule fr;
	int nbytes, nalloc, ret;
	u_char *buf, *new;

	assert(rule != NULL);

	nbytes = nalloc = sizeof(*ipfw);
	if ((buf = malloc(nbytes)) == NULL)
		return (-1);
	
	while (nbytes >= nalloc) {
		nalloc = nalloc * 2 + 200;
		nbytes = nalloc;
		if ((new = realloc(buf, nbytes)) == NULL) {
			if (buf)
				free(buf);
			return (-1);
		}
		buf = new;
		if (getsockopt(fw->fd, IPPROTO_IP, IP_FW_GET,
			       buf, &nbytes) < 0) {
			free(buf);
			return (-1);
		}
	}
	ret = -1;

	/* XXX - 65535 is the fixed ipfw default rule. */
	for (ipfw = (struct ip_fw *)buf; ipfw->fw_number < 65535; ipfw++) {
		ipfw_to_fr(ipfw, &fr);
		if (fw_cmp(&fr, rule) == 0) {
			if (setsockopt(fw->fd, IPPROTO_IP, IP_FW_DEL,
			    ipfw, sizeof(*ipfw)) < 0)
				ret = -2;
			else
				ret = 0;
			break;
		}
	}
	free(buf);
	
	if (ret < 0) {
		if (ret == -1)
			errno = ESRCH;
		return (-1);
	}
	return (0);
}

int
fw_loop(fw_t *fw, fw_handler callback, void *arg)
{
	struct ip_fw *ipfw;
	struct fw_rule fr;
	int i, cnt, nbytes, nalloc, ret;
	u_char *buf, *new;

	nbytes = nalloc = sizeof(*ipfw);
	if ((buf = malloc(nbytes)) == NULL)
		return (-1);
	
	while (nbytes >= nalloc) {
		nalloc = nalloc * 2 + 200;
		nbytes = nalloc;
		if ((new = realloc(buf, nbytes)) == NULL) {
			if (buf)
				free(buf);
			return (-1);
		}
		buf = new;
		if (getsockopt(fw->fd, IPPROTO_IP, IP_FW_GET,
			       buf, &nbytes) < 0) {
			free(buf);
			return (-1);
		}
	}
	cnt = nbytes / sizeof(*ipfw);
	ipfw = (struct ip_fw *)buf;
	ret = 0;
	
	for (i = 0; i < cnt; i++) {
		ipfw_to_fr(&ipfw[i], &fr);
		if ((ret = callback(&fr, arg)) != 0)
			break;
	}
	free(buf);
	return (ret);
}

fw_t *
fw_close(fw_t *fw)
{
	if (fw != NULL) {
		if (fw->fd >= 0)
			close(fw->fd);
		free(fw);
	}
	return (NULL);
}
