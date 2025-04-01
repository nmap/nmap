/*
 * ndisc-linux.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <asm/types.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <net/route.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct ndisc_handle
{
	int nlfd;
	int seq;
};

ndisc_t *
ndisc_open(void)
{
	struct sockaddr_nl snl;
	ndisc_t *n;

	if ((n = calloc(1, sizeof(*n))) != NULL) {
		n->nlfd = -1;

		if ((n->nlfd = socket(AF_NETLINK, SOCK_RAW,
			 NETLINK_ROUTE)) < 0)
			return (ndisc_close(n));

		memset(&snl, 0, sizeof(snl));
		snl.nl_family = AF_NETLINK;

		if (bind(n->nlfd, (struct sockaddr *)&snl, sizeof(snl)) < 0)
			return (ndisc_close(n));
	}
	return (n);
}

static int
netlink_addattr(struct nlmsghdr *n, int type, const void *data, int data_len)
{
	int len = RTA_LENGTH(data_len);
	struct rtattr *rta;

	rta = (struct rtattr *)((uint8_t*)n + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, data_len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

int
ndisc_modify(ndisc_t *n, const struct ndisc_entry *entry, int type, int flags)
{
	struct nlmsghdr *nmsg;
	struct ndmsg *ndm;
	struct sockaddr_nl snl;
	struct iovec iov;
	struct msghdr msg;
	u_char buf[512];
	int i, af, alen;

	switch (entry->ndisc_pa.addr_type) {
	case ADDR_TYPE_IP:
		af = AF_INET;
		alen = IP_ADDR_LEN;
		break;
	case ADDR_TYPE_IP6:
		af = AF_INET6;
		alen = IP6_ADDR_LEN;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	memset(buf, 0, sizeof(buf));

	nmsg = (struct nlmsghdr *)buf;
	nmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	nmsg->nlmsg_flags = NLM_F_REQUEST | flags;
	nmsg->nlmsg_type = type;
	nmsg->nlmsg_seq = ++n->seq;

	nmsg->nlmsg_flags |= NLM_F_ACK;

	ndm = (struct ndmsg *)(nmsg + 1);
	ndm->ndm_family = af;
	ndm->ndm_state = NUD_PERMANENT; 
	ndm->ndm_ifindex = entry->intf_index;

	netlink_addattr(nmsg, NDA_DST, &entry->ndisc_pa.addr_data8[0],
			alen);

	if (type == RTM_NEWNEIGH) {
		netlink_addattr(nmsg, NDA_LLADDR, 
				&entry->ndisc_ha.addr_data8[0], ETH_ADDR_LEN);
	}

	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;

	iov.iov_base = nmsg;
	iov.iov_len = nmsg->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &snl;
	msg.msg_namelen = sizeof(snl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(n->nlfd, &msg, 0) < 0)
		return (-1);

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	if ((i = recvmsg(n->nlfd, &msg, 0)) <= 0)
		return (-1);

	if (nmsg->nlmsg_len < (int)sizeof(*nmsg) || nmsg->nlmsg_len > i ||
	    nmsg->nlmsg_seq != n->seq) {
		errno = EINVAL;
		return (-1);
	}
	if (nmsg->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(nmsg);
		errno = -err->error;
		if (errno == 0) {
			return 0;
		}

		return (-1);
	}

	return (-1);
}

int
ndisc_add(ndisc_t *n, const struct ndisc_entry *entry)
{
	return ndisc_modify(n, entry, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL);
}

int
ndisc_delete(ndisc_t *n, const struct ndisc_entry *entry)
{
	return ndisc_modify(n, entry, RTM_DELNEIGH, 0);
}

int
ndisc_get(ndisc_t *n, struct ndisc_entry *entry)
{
	/* TBD */
	errno = ENOSYS;
	return (-1);
}

int
ndisc_loop(ndisc_t *n, ndisc_handler callback, void *arg)
{
	/* TBD */
	errno = ENOSYS;
	return (-1);
}

ndisc_t *
ndisc_close(ndisc_t *n)
{
	if (n != NULL) {
		if (n->nlfd >= 0)
			close(n->nlfd);
		free(n);
	}
	return (NULL);
}
