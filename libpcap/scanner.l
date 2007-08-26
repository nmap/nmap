%{
/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/libpcap/scanner.l,v 1.99.2.9 2007/06/11 09:52:05 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <string.h>

#include "pcap-int.h"

#include "gencode.h"
#ifdef INET6
#ifdef WIN32
#include <pcap-stdinc.h>

#ifdef __MINGW32__
#include "IP6_misc.h"
#endif
#else /* WIN32 */
#include <sys/socket.h>	/* for "struct sockaddr" in "struct addrinfo" */
#include <netdb.h>	/* for "struct addrinfo" */
#endif /* WIN32 */

/* Workaround for AIX 4.3 */
#if !defined(AI_NUMERICHOST)
#define AI_NUMERICHOST 0x04
#endif
#endif /*INET6*/
#include <pcap-namedb.h>
#include "tokdefs.h"

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

static int stoi(char *);
static inline int xdtoi(int);

#ifdef FLEX_SCANNER
#define YY_NO_UNPUT
static YY_BUFFER_STATE in_buffer;
#else
static char *in_buffer;

#undef getc
#define getc(fp)  (*in_buffer == 0 ? EOF : *in_buffer++)
#endif

#define yylval pcap_lval
extern YYSTYPE yylval;

%}

N		([0-9]+|(0X|0x)[0-9A-Fa-f]+)
B		([0-9A-Fa-f][0-9A-Fa-f]?)
W		([0-9A-Fa-f][0-9A-Fa-f]?[0-9A-Fa-f]?[0-9A-Fa-f]?)

%a 18400
%o 21500
%e 7600
%k 4550
%p 27600
%n 2000

V680		{W}:{W}:{W}:{W}:{W}:{W}:{W}:{W}

V670		::{W}:{W}:{W}:{W}:{W}:{W}:{W}
V671		{W}::{W}:{W}:{W}:{W}:{W}:{W}
V672		{W}:{W}::{W}:{W}:{W}:{W}:{W}
V673		{W}:{W}:{W}::{W}:{W}:{W}:{W}
V674		{W}:{W}:{W}:{W}::{W}:{W}:{W}
V675		{W}:{W}:{W}:{W}:{W}::{W}:{W}
V676		{W}:{W}:{W}:{W}:{W}:{W}::{W}
V677		{W}:{W}:{W}:{W}:{W}:{W}:{W}::

V660		::{W}:{W}:{W}:{W}:{W}:{W}
V661		{W}::{W}:{W}:{W}:{W}:{W}
V662		{W}:{W}::{W}:{W}:{W}:{W}
V663		{W}:{W}:{W}::{W}:{W}:{W}
V664		{W}:{W}:{W}:{W}::{W}:{W}
V665		{W}:{W}:{W}:{W}:{W}::{W}
V666		{W}:{W}:{W}:{W}:{W}:{W}::

V650		::{W}:{W}:{W}:{W}:{W}
V651		{W}::{W}:{W}:{W}:{W}
V652		{W}:{W}::{W}:{W}:{W}
V653		{W}:{W}:{W}::{W}:{W}
V654		{W}:{W}:{W}:{W}::{W}
V655		{W}:{W}:{W}:{W}:{W}::

V640		::{W}:{W}:{W}:{W}
V641		{W}::{W}:{W}:{W}
V642		{W}:{W}::{W}:{W}
V643		{W}:{W}:{W}::{W}
V644		{W}:{W}:{W}:{W}::

V630		::{W}:{W}:{W}
V631		{W}::{W}:{W}
V632		{W}:{W}::{W}
V633		{W}:{W}:{W}::

V620		::{W}:{W}
V621		{W}::{W}
V622		{W}:{W}::

V610		::{W}
V611		{W}::

V600		::

V6604		{W}:{W}:{W}:{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}

V6504		::{W}:{W}:{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}
V6514		{W}::{W}:{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}
V6524		{W}:{W}::{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}
V6534		{W}:{W}:{W}::{W}:{W}:{N}\.{N}\.{N}\.{N}
V6544		{W}:{W}:{W}:{W}::{W}:{N}\.{N}\.{N}\.{N}
V6554		{W}:{W}:{W}:{W}:{W}::{N}\.{N}\.{N}\.{N}

V6404		::{W}:{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}
V6414		{W}::{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}
V6424		{W}:{W}::{W}:{W}:{N}\.{N}\.{N}\.{N}
V6434		{W}:{W}:{W}::{W}:{N}\.{N}\.{N}\.{N}
V6444		{W}:{W}:{W}:{W}::{N}\.{N}\.{N}\.{N}

V6304		::{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}
V6314		{W}::{W}:{W}:{N}\.{N}\.{N}\.{N}
V6324		{W}:{W}::{W}:{N}\.{N}\.{N}\.{N}
V6334		{W}:{W}:{W}::{N}\.{N}\.{N}\.{N}

V6204		::{W}:{W}:{N}\.{N}\.{N}\.{N}
V6214		{W}::{W}:{N}\.{N}\.{N}\.{N}
V6224		{W}:{W}::{N}\.{N}\.{N}\.{N}

V6104		::{W}:{N}\.{N}\.{N}\.{N}
V6114		{W}::{N}\.{N}\.{N}\.{N}

V6004		::{N}\.{N}\.{N}\.{N}


V6		({V680}|{V670}|{V671}|{V672}|{V673}|{V674}|{V675}|{V676}|{V677}|{V660}|{V661}|{V662}|{V663}|{V664}|{V665}|{V666}|{V650}|{V651}|{V652}|{V653}|{V654}|{V655}|{V640}|{V641}|{V642}|{V643}|{V644}|{V630}|{V631}|{V632}|{V633}|{V620}|{V621}|{V622}|{V610}|{V611}|{V600}|{V6604}|{V6504}|{V6514}|{V6524}|{V6534}|{V6544}|{V6554}|{V6404}|{V6414}|{V6424}|{V6434}|{V6444}|{V6304}|{V6314}|{V6324}|{V6334}|{V6204}|{V6214}|{V6224}|{V6104}|{V6114}|{V6004})

%%
dst		return DST;
src		return SRC;

link|ether|ppp|slip  return LINK;
fddi|tr|wlan	return LINK;
arp		return ARP;
rarp		return RARP;
ip		return IP;
sctp		return SCTP;
tcp		return TCP;
udp		return UDP;
icmp		return ICMP;
igmp		return IGMP;
igrp		return IGRP;
pim		return PIM;
vrrp		return VRRP;
radio		return RADIO;

ip6		{
#ifdef INET6
		return IPV6;
#else
		bpf_error("%s not supported", yytext);
#endif
		}
icmp6		{
#ifdef INET6
		return ICMPV6;
#else
		bpf_error("%s not supported", yytext);
#endif
		}
ah		return AH;
esp		return ESP;

atalk		return ATALK;
aarp		return AARP;
decnet		return DECNET;
lat		return LAT;
sca		return SCA;
moprc		return MOPRC;
mopdl		return MOPDL;

iso		return ISO;
esis		return ESIS;
es-is		return ESIS;
isis		return ISIS;
is-is		return ISIS;
l1              return L1;
l2              return L2;
iih             return IIH;
lsp             return LSP;
snp             return SNP;
csnp            return CSNP;
psnp            return PSNP;

clnp		return CLNP;

stp		return STP;

ipx		return IPX;

netbeui		return NETBEUI;

host		return HOST;
net		return NET;
mask		return NETMASK;
port		return PORT;
portrange	return PORTRANGE;
proto		return PROTO;
protochain	{
#ifdef NO_PROTOCHAIN
		  bpf_error("%s not supported", yytext);
#else
		  return PROTOCHAIN;
#endif
		}

gateway		return GATEWAY;

less		return LESS;
greater		return GREATER;
byte		return CBYTE;
broadcast	return TK_BROADCAST;
multicast	return TK_MULTICAST;

and|"&&"	return AND;
or|"||"		return OR;
not		return '!';

len|length	return LEN;
inbound		return INBOUND;
outbound	return OUTBOUND;

vlan		return VLAN;
mpls		return MPLS;
pppoed		return PPPOED;
pppoes		return PPPOES;

lane		return LANE;
llc		return LLC;
metac		return METAC;
bcc		return BCC;
oam		return OAM;
oamf4		return OAMF4;
oamf4ec		return OAMF4EC;
oamf4sc		return OAMF4SC;
sc		return SC;
ilmic		return ILMIC;
vpi		return VPI;
vci		return VCI;
connectmsg	return CONNECTMSG;
metaconnect	return METACONNECT;

on|ifname	return PF_IFNAME;
rset|ruleset	return PF_RSET;
rnr|rulenum	return PF_RNR;
srnr|subrulenum	return PF_SRNR;
reason		return PF_REASON;
action		return PF_ACTION;

fisu		return FISU;
lssu		return LSSU;
lsu		return LSSU;
msu		return MSU;
sio		return SIO;
opc		return OPC;
dpc		return DPC;
sls		return SLS;

[ \r\n\t]		;
[+\-*/:\[\]!<>()&|=]	return yytext[0];
">="			return GEQ;
"<="			return LEQ;
"!="			return NEQ;
"=="			return '=';
"<<"			return LSH;
">>"			return RSH;
${B}			{ yylval.e = pcap_ether_aton(((char *)yytext)+1);
			  return AID; }
{N}			{ yylval.i = stoi((char *)yytext); return NUM; }
({N}\.{N})|({N}\.{N}\.{N})|({N}\.{N}\.{N}\.{N})	{
			yylval.s = sdup((char *)yytext); return HID; }
{B}:{B}:{B}:{B}:{B}:{B} { yylval.e = pcap_ether_aton((char *)yytext);
			  return EID; }
{V6}			{
#ifdef INET6
			  struct addrinfo hints, *res;
			  memset(&hints, 0, sizeof(hints));
			  hints.ai_family = AF_INET6;
			  hints.ai_flags = AI_NUMERICHOST;
			  if (getaddrinfo(yytext, NULL, &hints, &res))
				bpf_error("bogus IPv6 address %s", yytext);
			  else {
				yylval.s = sdup((char *)yytext); return HID6;
			  }
#else
			  bpf_error("IPv6 address %s not supported", yytext);
#endif /*INET6*/
			}
{B}:+({B}:+)+		{ bpf_error("bogus ethernet address %s", yytext); }
icmptype		{ yylval.i = 0; return NUM; }
icmpcode		{ yylval.i = 1; return NUM; }
icmp-echoreply		{ yylval.i = 0; return NUM; }
icmp-unreach		{ yylval.i = 3; return NUM; }
icmp-sourcequench	{ yylval.i = 4; return NUM; }
icmp-redirect		{ yylval.i = 5; return NUM; }
icmp-echo		{ yylval.i = 8; return NUM; }
icmp-routeradvert	{ yylval.i = 9; return NUM; }
icmp-routersolicit	{ yylval.i = 10; return NUM; }
icmp-timxceed		{ yylval.i = 11; return NUM; }
icmp-paramprob		{ yylval.i = 12; return NUM; }
icmp-tstamp		{ yylval.i = 13; return NUM; }
icmp-tstampreply	{ yylval.i = 14; return NUM; }
icmp-ireq		{ yylval.i = 15; return NUM; }
icmp-ireqreply		{ yylval.i = 16; return NUM; }
icmp-maskreq		{ yylval.i = 17; return NUM; }
icmp-maskreply		{ yylval.i = 18; return NUM; }
tcpflags		{ yylval.i = 13; return NUM; }
tcp-fin			{ yylval.i = 0x01; return NUM; }
tcp-syn			{ yylval.i = 0x02; return NUM; }
tcp-rst			{ yylval.i = 0x04; return NUM; }
tcp-push		{ yylval.i = 0x08; return NUM; }
tcp-ack			{ yylval.i = 0x10; return NUM; }
tcp-urg			{ yylval.i = 0x20; return NUM; }
[A-Za-z0-9]([-_.A-Za-z0-9]*[.A-Za-z0-9])? {
			 yylval.s = sdup((char *)yytext); return ID; }
"\\"[^ !()\n\t]+	{ yylval.s = sdup((char *)yytext + 1); return ID; }
[^ \[\]\t\n\-_.A-Za-z0-9!<>()&|=]+ {
			bpf_error("illegal token: %s", yytext); }
.			{ bpf_error("illegal char '%c'", *yytext); }
%%
void
lex_init(buf)
	const char *buf;
{
#ifdef FLEX_SCANNER
	in_buffer = yy_scan_string(buf);
#else
	in_buffer = buf;
#endif
}

/*
 * Do any cleanup necessary after parsing.
 */
void
lex_cleanup()
{
#ifdef FLEX_SCANNER
	if (in_buffer != NULL)
		yy_delete_buffer(in_buffer);
	in_buffer = NULL;
#endif
}

/*
 * Also define a yywrap.  Note that if we're using flex, it will
 * define a macro to map this identifier to pcap_wrap.
 */
int
yywrap()
{
	return 1;
}

/* Hex digit to integer. */
static inline int
xdtoi(c)
	register int c;
{
	if (isdigit(c))
		return c - '0';
	else if (islower(c))
		return c - 'a' + 10;
	else
		return c - 'A' + 10;
}

/*
 * Convert string to integer.  Just like atoi(), but checks for
 * preceding 0x or 0 and uses hex or octal instead of decimal.
 */
static int
stoi(s)
	char *s;
{
	int base = 10;
	int n = 0;

	if (*s == '0') {
		if (s[1] == 'x' || s[1] == 'X') {
			s += 2;
			base = 16;
		}
		else {
			base = 8;
			s += 1;
		}
	}
	while (*s)
		n = n * base + xdtoi(*s++);

	return n;
}
