/*
 * fw-pktfilter.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 * Copyright (c) 2001 Jean-Baptiste Marchand, Hervé Schauer Consultants.  
 *
 * $Id: fw-pktfilter.c,v 1.4 2005/02/15 06:37:06 dugsong Exp $
 */

#include "config.h"

#include <iphlpapi.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

#define PKTFILTER_PIPE "\\\\.\\pipe\\PktFltPipe"	
#define MAX_RULE_LENGTH 256

#define FILTER_FAILURE 0 /* filter had a syntax error */
#define FILTER_SUCCESS 1 /* filter was correctly added */
#define FILTER_MESSAGE 2 /* informative message returned to the client */

char *icmp_types[] = {
	"echorep",	/* 0: echo reply */
	"",		/* 1: unused */
	"",		/* 2: unused */
	"unreach",	/* 3: destination unreachable */
	"squench",	/* 4: source quench */
	"redir",	/* 5: redirect */
	"",		/* 6: unused */
	"",		/* 7: unused */
	"echo",		/* 8: echo request */
	"router_adv",	/* 9: router advertisement */
	"router_sol",	/* 10: router solicitation */
	"timex",	/* 11: time exceeded */
	"paramprob",	/* 12: parameter problem */
	"timest",	/* 13: timestamp request */
	"timestrep",	/* 14: timestamp reply */
	"inforeq",	/* 15: information request */
	"inforep",	/* 16: information reply */
	"maskreq",	/* 17: address mask request */
	"maskrep",	/* 18: address mask reply */
	NULL
};

struct fw_handle {
	IP_ADAPTER_INFO *ifinfo;
	/* XXX - rules cache for delete lookup? */
};

static int
parse_addr(char *p, struct addr *a)
{
	if (strcmp(p, "any") == 0)
		return (addr_aton("0.0.0.0/0", a));
	return (addr_aton(p, a));
}

static int
parse_portspec(char *str, uint16_t *ports)
{
	char *p = strsep(&str, " ");
	
	if (p[0] == '=') {
		ports[0] = ports[1] = atoi(strsep(&str, " "));
	} else if (p[0] == '<') {
		ports[1] = atoi(strsep(&str, " "));
		if (p[1] != '=') ports[1]--;
	} else if (p[0] == '>') {
		ports[1] = TCP_PORT_MAX;
		ports[0] = atoi(strsep(&str, " "));
		if (p[1] != '=') ports[0]++;
	} else if (p[0] != '\0') {
		if (strcmp(strsep(&str, " "), "><") != 0)
			return (-1);
		ports[0] = atoi(p) + 1;
		ports[1] = atoi(strsep(&str, " ")) - 1;
	}
	return (0);
}

static int
parse_icmpspec(char *str, uint16_t *type, uint16_t *code)
{
	char *p, *e;
	int i;

	p = strsep(&str, " ");
	for (i = 0; icmp_types[i] && strcmp(p, icmp_types[i]); i++)
		;
	if (icmp_types[i] == NULL) {
		i = strtol(p, &e, 10);
		if (*e != '\0')
			return (-1);
	}
	type[0] = i;
	type[1] = 0xff;
	
	p = strsep(&str, " ");
	if (p != NULL && strcmp(p, "code")) {
		p = strsep(&str, " ");
		i = strtol(p, &e, 10);
		if (*e != '\0')
			return (-1);
		code[0] = i;
		code[1] = 0xff;
	}
	return (0);
}

/*
  <op> <dir> on <device> all
  <op> <dir> on <device> proto <proto> all
  <op> <dir> on <device> proto <proto> from <src> [ports] to <dst> [ports]
  <op> <dir> on <device> proto icmp all [icmp-type <type> [code <code>]]
  <op> <dir> on <device> proto icmp from <src> to <dst> [icmp-type <type> [code <code>]]
*/
static int
parse_rule(char *str, struct fw_rule *rule)
{
	char *p, *q;
	
	memset(rule, 0, sizeof(*rule));
	
	/* action */
	p = strsep(&str, " ");
	if (strcmp(p, "block") == 0)
		rule->fw_op = FW_OP_BLOCK;
	else if (strcmp(p, "pass") == 0)
		rule->fw_op = FW_OP_ALLOW;
	else return (-1);
	
	/* direction */
	p = strsep(&str, " ");
	if (strcmp(p, "in") == 0)
		rule->fw_dir = FW_DIR_IN;
	else if (strcmp(p, "out") == 0)
		rule->fw_dir = FW_DIR_OUT;
	else return (-1);

	/* device */
	if (strcmp(strsep(&str, " "), "on") != 0)
		return (-1);
	p = strsep(&str, " ");
	/* XXX - handle bug in pktfltsrv.c */
	if ((q = strstr(p, "proto")) != NULL)
		*q = '\0';
	if (strcmp(p, "all") != 0)
		strlcpy(rule->fw_device, p, sizeof(rule->fw_device));
	
	/* proto */
	p = strsep(&str, " ");
	/* XXX - handle bug in pktfltsrv.c */
	if (strcmp(p, "proto") == 0)
		p = strsep(&str, " ");
	/* XXX - handle default rules */
	if (strcmp(p, "all") == 0)
		return (0);
	if (strcmp(p, "icmp") == 0)
		rule->fw_proto = IP_PROTO_ICMP;
	else if (strcmp(p, "tcp") == 0)
		rule->fw_proto = IP_PROTO_TCP;
	else if (strcmp(p, "udp") == 0)
		rule->fw_proto = IP_PROTO_UDP;
	else rule->fw_proto = atoi(p);
	
	/* source */
	p = strsep(&str, " ");
	if (strcmp(p, "all") == 0)
		return (0);
	if (strcmp(p, "from") != 0)
		goto icmp_type_code;
	p = strsep(&str, " ");
	if (parse_addr(p, &rule->fw_src) < 0)
		return (-1);
	
	/* source port */
	p = strsep(&str, " ");
	if (strcmp(p, "port") == 0) {
		if ((p = strstr(str, " to ")) == NULL)
			return (-1);
		*p++ = '\0';
		if (parse_portspec(str, rule->fw_sport) < 0)
			return (-1);
		str = p + 3;
	} else if (strcmp(p, "to") != 0)
		return (-1);
	
	/* destination */
	p = strsep(&str, " ");
	if (parse_addr(p, &rule->fw_dst) < 0)
		return (-1);

	/* destination port */
	p = strsep(&str, " ");
	if (strcmp(p, "port") == 0)
		return (parse_portspec(str, rule->fw_dport));

 icmp_type_code:
	/* icmp-type, code */
	if (strcmp(p, "icmp-type") == 0) {
		if (parse_icmpspec(str, rule->fw_sport, rule->fw_dport) < 0)
			return (-1);
	}
	return (0);
}

static int
format_rule(const struct fw_rule *rule, char *buf, int len)
{
	char tmp[128];
	
	strlcpy(buf, (rule->fw_op == FW_OP_ALLOW) ? "pass " : "block ", len);
	strlcat(buf, (rule->fw_dir == FW_DIR_IN) ? "in " : "out ", len);
	snprintf(tmp, sizeof(tmp), "on %s ", rule->fw_device);
	strlcat(buf, tmp, len);
	if (rule->fw_proto != 0) {
		snprintf(tmp, sizeof(tmp), "proto %d ", rule->fw_proto);
		strlcat(buf, tmp, len);
	}
	/* source */
	if (rule->fw_src.addr_type != ADDR_TYPE_NONE) {
		snprintf(tmp, sizeof(tmp), "from %s ",
		    addr_ntoa(&rule->fw_src));
		strlcat(buf, tmp, len);
	} else
		strlcat(buf, "from any ", len);
	
	/* sport */
	if (rule->fw_proto == IP_PROTO_TCP || rule->fw_proto == IP_PROTO_UDP) {
		if (rule->fw_sport[0] == rule->fw_sport[1])
			snprintf(tmp, sizeof(tmp), "port = %d ",
			    rule->fw_sport[0]);
		else
			snprintf(tmp, sizeof(tmp), "port %d >< %d ",
			    rule->fw_sport[0] - 1, rule->fw_sport[1] + 1);
		strlcat(buf, tmp, len);
	}
	/* destination */
	if (rule->fw_dst.addr_type != ADDR_TYPE_NONE) {
		snprintf(tmp, sizeof(tmp), "to %s ",
		    addr_ntoa(&rule->fw_dst));
		strlcat(buf, tmp, len);
	} else
		strlcat(buf, "to any ", len);
	
	/* dport */
	if (rule->fw_proto == IP_PROTO_TCP || rule->fw_proto == IP_PROTO_UDP) {
		if (rule->fw_dport[0] == rule->fw_dport[1])
			snprintf(tmp, sizeof(tmp), "port = %d",
			    rule->fw_dport[0]);
		else
			snprintf(tmp, sizeof(tmp), "port %d >< %d",
			    rule->fw_dport[0] - 1, rule->fw_dport[1] + 1);
		strlcat(buf, tmp, len);
	} else if (rule->fw_proto == IP_PROTO_ICMP) {
		if (rule->fw_sport[1]) {
			snprintf(tmp, sizeof(tmp), "icmp-type %d",
			    rule->fw_sport[0]);
			strlcat(buf, tmp, len);
			if (rule->fw_dport[1]) {
				snprintf(tmp, sizeof(tmp), " code %d",
				    rule->fw_dport[0]);
				strlcat(buf, tmp, len);
			}
		}
	}
	return (strlen(buf));
}

static char *
call_pipe(const char *msg, int len)
{
	HANDLE *pipe;
	DWORD i;
	char *p, *reply, status;
	
	if (!WaitNamedPipe(PKTFILTER_PIPE, NMPWAIT_USE_DEFAULT_WAIT) ||
	    (pipe = CreateFile(PKTFILTER_PIPE, GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE) {
		return (NULL);
	}
	reply = NULL;
	
	if (WriteFile(pipe, msg, len, &i, NULL)) {
		if (ReadFile(pipe, &status, sizeof(status), &i, NULL)) {
			if (status == FILTER_FAILURE) {
				ReadFile(pipe, &status, sizeof(status),
				    &i, NULL);
			} else if (status == FILTER_MESSAGE) {
				/* get msg length */
				if (ReadFile(pipe, &len, 4, &i, NULL)) {
					/* get msg */
					p = reply = calloc(1, len + 1);
					if (!ReadFile(pipe, reply, len,
						&i, NULL)) {
						free(reply);
						reply = NULL;
					}
				}
			} else if (status == FILTER_SUCCESS)
				reply = strdup("");	/* XXX */
		}
	}
	CloseHandle(pipe);
	return (reply);
}

fw_t *
fw_open(void)
{
	fw_t *f;
	IP_ADAPTER_INFO *ifinfo;
	ULONG size;
	
	if ((f = calloc(1, sizeof(*f))) == NULL)
		return (NULL);
	
	size = sizeof(*f->ifinfo);
	f->ifinfo = malloc(size);
	if (GetAdaptersInfo(f->ifinfo, &size) != ERROR_SUCCESS) {
		free(f->ifinfo);
		f->ifinfo = malloc(size);
		GetAdaptersInfo(f->ifinfo, &size);
	}
	/* XXX - normalize interface names. */
	for (ifinfo = f->ifinfo; ifinfo != NULL; ifinfo = ifinfo->Next) {
		char *fmt;
		if (ifinfo->Type == MIB_IF_TYPE_ETHERNET)
			fmt = "eth";
		else if (ifinfo->Type == MIB_IF_TYPE_PPP)
			fmt = "ppp";
		else if (ifinfo->Type == MIB_IF_TYPE_SLIP)
			fmt = "sl";
		else if (ifinfo->Type == MIB_IF_TYPE_LOOPBACK)
			fmt = "lo";
		else if (ifinfo->Type == MIB_IF_TYPE_TOKENRING)
			fmt = "tr";
		else if (ifinfo->Type == MIB_IF_TYPE_FDDI)
			fmt = "fd";
		else 
			fmt = "if";
		sprintf(ifinfo->AdapterName, "%s%lu", fmt, ifinfo->ComboIndex);
	}
	return (f);
}

int
fw_add(fw_t *f, const struct fw_rule *rule)
{
	char *p, buf[MAX_RULE_LENGTH];
	int len;
	
	len = format_rule(rule, buf, sizeof(buf));
	
	if ((p = call_pipe(buf, len)) == NULL)
		return (-1);
	free(p);
	return (0);
}

int
fw_delete(fw_t *f, const struct fw_rule *rule)
{
	struct fw_rule tmp;
	char *p, *line, *msg, cmd[128], buf[MAX_RULE_LENGTH];
	int n, ruleno, len;
	
	format_rule(rule, buf, sizeof(buf));
	
	len = snprintf(cmd, sizeof(cmd), "List on %s", rule->fw_device);
	if ((msg = call_pipe(cmd, len)) == NULL)
		return (-1);

	for (ruleno = 0, p = msg; (line = strsep(&p, "\r\n")) != NULL; ) {
		if (strncmp(line, "rule ", 5) == 0) {
			line += 5;
			n = atoi(strsep(&line, ":"));
			if (parse_rule(line + 1, &tmp) == 0 &&
			    memcmp(&tmp, rule, sizeof(tmp)) == 0) {
				ruleno = n;
				break;
			}
		}
	}
	free(msg);
	if (ruleno == 0) {
		errno = ENXIO;
		SetLastError(ERROR_NO_DATA);
		return (-1);
	}
	len = snprintf(cmd, sizeof(cmd), "delete %d on %s",
	    ruleno, rule->fw_device);
	if ((p = call_pipe(cmd, len)) == NULL)
		return (-1);
	free(p);

	return (0);
}

int
fw_loop(fw_t *f, fw_handler callback, void *arg)
{
	struct fw_rule rule;
	IP_ADAPTER_INFO *ifinfo;
	char *p, *line, *msg, buf[MAX_RULE_LENGTH];
	int len, ret;

	for (ret = 0, ifinfo = f->ifinfo; ret == 0 && ifinfo != NULL;
	    ifinfo = ifinfo->Next) {
		len = snprintf(buf, sizeof(buf), "list on %s",
		    ifinfo->AdapterName);
		if ((msg = call_pipe(buf, len)) == NULL)
			return (-1);
		
		/* parse msg */
		for (p = msg; (line = strsep(&p, "\r\n")) != NULL; ) {
			if (*line == '\0' || *line == '#' || isspace(*line))
				continue;
			if (parse_rule(line, &rule) == 0) {
				if ((ret = callback(&rule, arg)) != 0)
					break;
			}
		}
		free(msg);
	}
	return (ret);
}

fw_t *
fw_close(fw_t *f)
{
	if (f != NULL) {
		free(f->ifinfo);
		free(f);
	}
	return (NULL);
}
