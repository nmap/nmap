/*
 * fw-pf.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: fw-pf.c,v 1.20 2005/02/14 20:43:32 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

/*
 * XXX - cope with moving pf API
 */
#if defined(DIOCRCLRTABLES)
/* XXX - can't isolate the following change:
 *     $OpenBSD: pfvar.h,v 1.112 2002/12/17 12:30:13 mcbride Exp $
 *  so i'll take 1.119's DIOCRCLRTABLES - 12 days of pf unsupported.
 */
# define HAVE_PF_CHANGE_GET_TICKET	1
/* OpenBSD 3.3+ - 3.6 */
/*     $OpenBSD: pfvar.h,v 1.197 2004/06/14 20:53:27 cedric Exp $ */
/*     $OpenBSD: pfvar.h,v 1.130 2003/01/09 10:40:45 cedric Exp $ */
/*     $OpenBSD: pfvar.h,v 1.127 2003/01/05 22:14:23 dhartmei Exp $ */
# define PFRA_ADDR(ra)	(ra)->addr.v.a.addr.v4.s_addr
# define PFRA_MASK(ra)	(ra)->addr.v.a.mask.v4.s_addr
# define pfioc_changerule	pfioc_rule
# define oldrule	rule
# define newrule	rule
#elif defined(DIOCBEGINADDRS)
/*     $OpenBSD: pfvar.h,v 1.102 2002/11/23 05:16:58 mcbride Exp $ */
# define PFRA_ADDR(ra)	(ra)->addr.addr.v4.s_addr
# define PFRA_MASK(ra)	(ra)->addr.mask.v4.s_addr
#elif defined(PFRULE_FRAGMENT)
/* OpenBSD 3.2 */
/*     $OpenBSD: pfvar.h,v 1.68 2002/04/24 18:10:25 dhartmei Exp $ */
# define PFRA_ADDR(ra)	(ra)->addr.addr.v4.s_addr
# define PFRA_MASK(ra)	(ra)->mask.v4.s_addr
#elif defined (PF_AEQ)
/* OpenBSD 3.1 */
/*     $OpenBSD: pfvar.h,v 1.51 2001/09/15 03:54:40 frantzen Exp $ */
# define PFRA_ADDR(ra)	(ra)->addr.v4.s_addr
# define PFRA_MASK(ra)	(ra)->mask.v4.s_addr
#else
/* OpenBSD 3.0 */
# define PFRA_ADDR(ra)	(ra)->addr
# define PFRA_ADDR(ra)	(ra)->mask
#endif

struct fw_handle {
	int	fd;
};

static void
fr_to_pr(const struct fw_rule *fr, struct pf_rule *pr)
{
	memset(pr, 0, sizeof(*pr));
	
	strlcpy(pr->ifname, fr->fw_device, sizeof(pr->ifname));
	
	pr->action = (fr->fw_op == FW_OP_ALLOW) ? PF_PASS : PF_DROP;
	pr->direction = (fr->fw_dir == FW_DIR_IN) ? PF_IN : PF_OUT;
	pr->proto = fr->fw_proto;

	pr->af = AF_INET;
	PFRA_ADDR(&pr->src) = fr->fw_src.addr_ip;
	addr_btom(fr->fw_src.addr_bits, &(PFRA_MASK(&pr->src)), IP_ADDR_LEN);
	
	PFRA_ADDR(&pr->dst) = fr->fw_dst.addr_ip;
	addr_btom(fr->fw_dst.addr_bits, &(PFRA_MASK(&pr->dst)), IP_ADDR_LEN);
	
	switch (fr->fw_proto) {
	case IP_PROTO_ICMP:
		if (fr->fw_sport[1])
			pr->type = (u_char)(fr->fw_sport[0] &
			    fr->fw_sport[1]) + 1;
		if (fr->fw_dport[1])
			pr->code = (u_char)(fr->fw_dport[0] &
			    fr->fw_dport[1]) + 1;
		break;
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		pr->src.port[0] = htons(fr->fw_sport[0]);
		pr->src.port[1] = htons(fr->fw_sport[1]);
		if (pr->src.port[0] == pr->src.port[1]) {
			pr->src.port_op = PF_OP_EQ;
		} else
			pr->src.port_op = PF_OP_IRG;

		pr->dst.port[0] = htons(fr->fw_dport[0]);
		pr->dst.port[1] = htons(fr->fw_dport[1]);
		if (pr->dst.port[0] == pr->dst.port[1]) {
			pr->dst.port_op = PF_OP_EQ;
		} else
			pr->dst.port_op = PF_OP_IRG;
		break;
	}
}

static int
pr_to_fr(const struct pf_rule *pr, struct fw_rule *fr)
{
	memset(fr, 0, sizeof(*fr));
	
	strlcpy(fr->fw_device, pr->ifname, sizeof(fr->fw_device));

	if (pr->action == PF_DROP)
		fr->fw_op = FW_OP_BLOCK;
	else if (pr->action == PF_PASS)
		fr->fw_op = FW_OP_ALLOW;
	else
		return (-1);
	
	fr->fw_dir = pr->direction == PF_IN ? FW_DIR_IN : FW_DIR_OUT;
	fr->fw_proto = pr->proto;

	if (pr->af != AF_INET)
		return (-1);
	
	fr->fw_src.addr_type = ADDR_TYPE_IP;
	addr_mtob(&(PFRA_MASK(&pr->src)), IP_ADDR_LEN, &fr->fw_src.addr_bits);
	fr->fw_src.addr_ip = PFRA_ADDR(&pr->src);
	
 	fr->fw_dst.addr_type = ADDR_TYPE_IP;
	addr_mtob(&(PFRA_MASK(&pr->dst)), IP_ADDR_LEN, &fr->fw_dst.addr_bits);
	fr->fw_dst.addr_ip = PFRA_ADDR(&pr->dst);
	
	switch (fr->fw_proto) {
	case IP_PROTO_ICMP:
		if (pr->type) {
			fr->fw_sport[0] = pr->type - 1;
			fr->fw_sport[1] = 0xff;
		}
		if (pr->code) {
			fr->fw_dport[0] = pr->code - 1;
			fr->fw_dport[1] = 0xff;
		}
		break;
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		fr->fw_sport[0] = ntohs(pr->src.port[0]);
		fr->fw_sport[1] = ntohs(pr->src.port[1]);
		if (pr->src.port_op == PF_OP_EQ)
			fr->fw_sport[1] = fr->fw_sport[0];

		fr->fw_dport[0] = ntohs(pr->dst.port[0]);
		fr->fw_dport[1] = ntohs(pr->dst.port[1]);
		if (pr->dst.port_op == PF_OP_EQ)
			fr->fw_dport[1] = fr->fw_dport[0];
	}
	return (0);
}

#ifdef HAVE_PF_CHANGE_GET_TICKET
static int
_fw_cmp(const struct fw_rule *a, const struct fw_rule *b)
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
#endif

fw_t *
fw_open(void)
{
	fw_t *fw;

	if ((fw = calloc(1, sizeof(*fw))) != NULL) {
		if ((fw->fd = open("/dev/pf", O_RDWR)) < 0)
			return (fw_close(fw));
	}
	return (fw);
}

int
fw_add(fw_t *fw, const struct fw_rule *rule)
{
	struct pfioc_changerule pcr;

	assert(fw != NULL && rule != NULL);
	memset(&pcr, 0, sizeof(pcr));
#ifdef HAVE_PF_CHANGE_GET_TICKET
	{
		struct fw_rule fr;
		
		if (ioctl(fw->fd, DIOCGETRULES, &pcr) < 0)
			return (-1);
		while ((int)--pcr.nr >= 0) {
			if (ioctl(fw->fd, DIOCGETRULE, &pcr) == 0 &&
			    pr_to_fr(&pcr.rule, &fr) == 0) {
				if (_fw_cmp(rule, &fr) == 0) {
					errno = EEXIST;
					return (-1);
				}
			}
		}
	}
#endif
#ifdef DIOCBEGINADDRS
	{
		struct pfioc_pooladdr ppa;
		
		if (ioctl(fw->fd, DIOCBEGINADDRS, &ppa) < 0)
			return (-1);
		pcr.pool_ticket = ppa.ticket;
	}
#endif
	pcr.action = PF_CHANGE_ADD_TAIL;
	fr_to_pr(rule, &pcr.newrule);
	
	return (ioctl(fw->fd, DIOCCHANGERULE, &pcr));
}

int
fw_delete(fw_t *fw, const struct fw_rule *rule)
{
	struct pfioc_changerule pcr;
	
	assert(fw != NULL && rule != NULL);
	memset(&pcr, 0, sizeof(pcr));
#ifdef HAVE_PF_CHANGE_GET_TICKET
	{
		struct fw_rule fr;
		int found = 0;
		
		if (ioctl(fw->fd, DIOCGETRULES, &pcr) < 0)
			return (-1);
		while ((int)--pcr.nr >= 0) {
			if (ioctl(fw->fd, DIOCGETRULE, &pcr) == 0 &&
			    pr_to_fr(&pcr.rule, &fr) == 0) {
				if (_fw_cmp(rule, &fr) == 0) {
					found = 1;
					break;
				}
			}
		}
		if (!found) {
			errno = ENOENT;
			return (-1);
		}
	}
#endif
#ifdef DIOCBEGINADDRS
	{
		struct pfioc_pooladdr ppa;
		
		if (ioctl(fw->fd, DIOCBEGINADDRS, &ppa) < 0)
			return (-1);
		pcr.pool_ticket = ppa.ticket;
	}
#endif
	pcr.action = PF_CHANGE_REMOVE;
	fr_to_pr(rule, &pcr.oldrule);
	
	return (ioctl(fw->fd, DIOCCHANGERULE, &pcr));
}

int
fw_loop(fw_t *fw, fw_handler callback, void *arg)
{
	struct pfioc_rule pr;
	struct fw_rule fr;
	uint32_t n, max;
	int ret = 0;

	memset(&pr, 0, sizeof(pr));
	if (ioctl(fw->fd, DIOCGETRULES, &pr) < 0)
		return (-1);
	
	for (n = 0, max = pr.nr; n < max; n++) {
		pr.nr = n;
		
		if ((ret = ioctl(fw->fd, DIOCGETRULE, &pr)) < 0)
			break;
		if (pr_to_fr(&pr.rule, &fr) < 0)
			continue;
		if ((ret = callback(&fr, arg)) != 0)
			break;
	}
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
