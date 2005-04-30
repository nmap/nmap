/*
 * fw-ipchains.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: fw-ipchains.c,v 1.8 2004/05/05 21:25:20 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#undef __USE_BSD
#include <netinet/ip_icmp.h>
#include <linux/if.h>
#ifdef HAVE_LINUX_IP_FW_H
#include <linux/ip_fw.h>
#elif defined(HAVE_LINUX_IP_FWCHAINS_H)
#include <linux/ip_fwchains.h>
#elif defined(HAVE_LINUX_NETFILTER_IPV4_IPCHAINS_CORE_H)
#include <linux/netfilter_ipv4/ipchains_core.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

#define PROC_IPCHAINS_FILE	"/proc/net/ip_fwchains"

struct fw_handle {
	int	fd;
};

static void
fr_to_fwc(const struct fw_rule *fr, struct ip_fwchange *fwc)
{
	memset(fwc, 0, sizeof(*fwc));

	strlcpy(fwc->fwc_rule.ipfw.fw_vianame, fr->fw_device, IFNAMSIZ);
	
	if (fr->fw_op == FW_OP_ALLOW)
		strlcpy(fwc->fwc_rule.label, IP_FW_LABEL_ACCEPT, 
		    sizeof(fwc->fwc_rule.label));
	else
		strlcpy(fwc->fwc_rule.label, IP_FW_LABEL_BLOCK,
		    sizeof(fwc->fwc_rule.label));

	if (fr->fw_dir == FW_DIR_IN)
		strlcpy(fwc->fwc_label, IP_FW_LABEL_INPUT,
		    sizeof(fwc->fwc_label));
	else
		strlcpy(fwc->fwc_label, IP_FW_LABEL_OUTPUT,
		    sizeof(fwc->fwc_label));
	
	fwc->fwc_rule.ipfw.fw_proto = fr->fw_proto;
	fwc->fwc_rule.ipfw.fw_src.s_addr = fr->fw_src.addr_ip;
	fwc->fwc_rule.ipfw.fw_dst.s_addr = fr->fw_dst.addr_ip;
	addr_btom(fr->fw_src.addr_bits, &fwc->fwc_rule.ipfw.fw_smsk.s_addr,
	    IP_ADDR_LEN);
	addr_btom(fr->fw_dst.addr_bits, &fwc->fwc_rule.ipfw.fw_dmsk.s_addr,
	    IP_ADDR_LEN);

	/* XXX - ICMP? */
	fwc->fwc_rule.ipfw.fw_spts[0] = fr->fw_sport[0];
	fwc->fwc_rule.ipfw.fw_spts[1] = fr->fw_sport[1];
	fwc->fwc_rule.ipfw.fw_dpts[0] = fr->fw_dport[0];
	fwc->fwc_rule.ipfw.fw_dpts[1] = fr->fw_dport[1];
}

static void
fwc_to_fr(const struct ip_fwchange *fwc, struct fw_rule *fr)
{
	memset(fr, 0, sizeof(*fr));

	strlcpy(fr->fw_device, fwc->fwc_rule.ipfw.fw_vianame,
	    sizeof(fr->fw_device));

	if (strcmp(fwc->fwc_rule.label, IP_FW_LABEL_ACCEPT) == 0)
		fr->fw_op = FW_OP_ALLOW;
	else
		fr->fw_op = FW_OP_BLOCK;

	if (strcmp(fwc->fwc_label, IP_FW_LABEL_INPUT) == 0)
		fr->fw_dir = FW_DIR_IN;
	else
		fr->fw_dir = FW_DIR_OUT;

	fr->fw_proto = fwc->fwc_rule.ipfw.fw_proto;
	fr->fw_src.addr_type = fr->fw_dst.addr_type = ADDR_TYPE_IP;
	fr->fw_src.addr_ip = fwc->fwc_rule.ipfw.fw_src.s_addr;
	fr->fw_dst.addr_ip = fwc->fwc_rule.ipfw.fw_dst.s_addr;
	addr_mtob(&fwc->fwc_rule.ipfw.fw_smsk.s_addr, IP_ADDR_LEN,
	    &fr->fw_src.addr_bits);
	addr_mtob(&fwc->fwc_rule.ipfw.fw_dmsk.s_addr, IP_ADDR_LEN,
	    &fr->fw_dst.addr_bits);

	/* XXX - ICMP? */
	fr->fw_sport[0] = fwc->fwc_rule.ipfw.fw_spts[0];
	fr->fw_sport[1] = fwc->fwc_rule.ipfw.fw_spts[1];
	fr->fw_dport[0] = fwc->fwc_rule.ipfw.fw_dpts[0];
	fr->fw_dport[1] = fwc->fwc_rule.ipfw.fw_dpts[1];
}

fw_t *
fw_open(void)
{
	fw_t *fw;

	if ((fw = calloc(1, sizeof(*fw))) != NULL) {
		if ((fw->fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
			return (fw_close(fw));
	}
	return (fw);
}

int
fw_add(fw_t *fw, const struct fw_rule *rule)
{
	struct ip_fwchange fwc;

	fr_to_fwc(rule, &fwc);
	
	return (setsockopt(fw->fd, IPPROTO_IP, IP_FW_APPEND,
	    &fwc, sizeof(fwc)));
}

int
fw_delete(fw_t *fw, const struct fw_rule *rule)
{
	struct ip_fwchange fwc;

	fr_to_fwc(rule, &fwc);
	
	return (setsockopt(fw->fd, IPPROTO_IP, IP_FW_DELETE,
	    &fwc, sizeof(fwc)));
}

int
fw_loop(fw_t *fw, fw_handler callback, void *arg)
{
	FILE *fp;
	struct ip_fwchange fwc;
	struct fw_rule fr;
	char buf[BUFSIZ];
	u_int phi, plo, bhi, blo, tand, txor;
	int ret;
	
	if ((fp = fopen(PROC_IPCHAINS_FILE, "r")) == NULL)
		return (-1);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (sscanf(buf,
		    "%8s %X/%X->%X/%X %s %hX %hX %hu %u %u %u %u "
		    "%hu-%hu %hu-%hu A%X X%X %hX %u %hu %s\n",
		    fwc.fwc_label,
		    &fwc.fwc_rule.ipfw.fw_src.s_addr,
		    &fwc.fwc_rule.ipfw.fw_smsk.s_addr,
		    &fwc.fwc_rule.ipfw.fw_dst.s_addr,
		    &fwc.fwc_rule.ipfw.fw_dmsk.s_addr,
		    fwc.fwc_rule.ipfw.fw_vianame,
		    &fwc.fwc_rule.ipfw.fw_flg,
		    &fwc.fwc_rule.ipfw.fw_invflg,
		    &fwc.fwc_rule.ipfw.fw_proto,
		    &phi, &plo, &bhi, &blo,
		    &fwc.fwc_rule.ipfw.fw_spts[0],
		    &fwc.fwc_rule.ipfw.fw_spts[1],
		    &fwc.fwc_rule.ipfw.fw_dpts[0],
		    &fwc.fwc_rule.ipfw.fw_dpts[1],
		    &tand, &txor,
		    &fwc.fwc_rule.ipfw.fw_redirpt,
		    &fwc.fwc_rule.ipfw.fw_mark,
		    &fwc.fwc_rule.ipfw.fw_outputsize,
		    fwc.fwc_rule.label) != 23)
			break;

		if (strcmp(fwc.fwc_rule.label, IP_FW_LABEL_ACCEPT) != 0 &&
		    strcmp(fwc.fwc_rule.label, IP_FW_LABEL_BLOCK) != 0 &&
		    strcmp(fwc.fwc_rule.label, IP_FW_LABEL_REJECT) != 0)
			continue;
		if (strcmp(fwc.fwc_label, IP_FW_LABEL_INPUT) != 0 &&
		    strcmp(fwc.fwc_label, IP_FW_LABEL_OUTPUT) != 0)
			continue;
		if (strcmp(fwc.fwc_rule.label, "-") == 0)
			(fwc.fwc_rule.label)[0] = '\0';
		if (strcmp(fwc.fwc_rule.ipfw.fw_vianame, "-") == 0)
			(fwc.fwc_rule.ipfw.fw_vianame)[0] = '\0';
		fwc.fwc_rule.ipfw.fw_src.s_addr =
		    htonl(fwc.fwc_rule.ipfw.fw_src.s_addr);
		fwc.fwc_rule.ipfw.fw_dst.s_addr =
		    htonl(fwc.fwc_rule.ipfw.fw_dst.s_addr);
		fwc.fwc_rule.ipfw.fw_smsk.s_addr =
		    htonl(fwc.fwc_rule.ipfw.fw_smsk.s_addr);
		fwc.fwc_rule.ipfw.fw_dmsk.s_addr =
		    htonl(fwc.fwc_rule.ipfw.fw_dmsk.s_addr);
		
		fwc_to_fr(&fwc, &fr);
		
		if ((ret = callback(&fr, arg)) != 0) {
			fclose(fp);
			return (ret);
		}
	}
	fclose(fp);
	
	return (0);
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
