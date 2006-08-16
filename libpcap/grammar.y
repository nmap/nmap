%{
/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996
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
 *
 */
#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/libpcap/grammar.y,v 1.86.2.5 2005/09/05 09:08:06 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include <pcap-stdinc.h>
#else /* WIN32 */
#include <sys/types.h>
#include <sys/socket.h>
#endif /* WIN32 */

#include <stdlib.h>

#ifndef WIN32
#if __STDC__
struct mbuf;
struct rtentry;
#endif

#include <netinet/in.h>
#endif /* WIN32 */

#include <stdio.h>

#include "pcap-int.h"

#include "gencode.h"
#include "pf.h"
#include <pcap-namedb.h>

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#define QSET(q, p, d, a) (q).proto = (p),\
			 (q).dir = (d),\
			 (q).addr = (a)

int n_errors = 0;

static struct qual qerr = { Q_UNDEF, Q_UNDEF, Q_UNDEF, Q_UNDEF };

static void
yyerror(char *msg)
{
	++n_errors;
	bpf_error("%s", msg);
	/* NOTREACHED */
}

#ifndef YYBISON
int yyparse(void);

int
pcap_parse()
{
	return (yyparse());
}
#endif

%}

%union {
	int i;
	bpf_u_int32 h;
	u_char *e;
	char *s;
	struct stmt *stmt;
	struct arth *a;
	struct {
		struct qual q;
		int atmfieldtype;
		int mtp3fieldtype;
		struct block *b;
	} blk;
	struct block *rblk;
}

%type	<blk>	expr id nid pid term rterm qid
%type	<blk>	head
%type	<i>	pqual dqual aqual ndaqual
%type	<a>	arth narth
%type	<i>	byteop pname pnum relop irelop
%type	<blk>	and or paren not null prog
%type	<rblk>	other pfvar
%type	<i>	atmtype atmmultitype
%type	<blk>	atmfield
%type	<blk>	atmfieldvalue atmvalue atmlistvalue
%type   <blk>   mtp3field
%type   <blk>   mtp3fieldvalue mtp3value mtp3listvalue


%token  DST SRC HOST GATEWAY
%token  NET NETMASK PORT PORTRANGE LESS GREATER PROTO PROTOCHAIN CBYTE
%token  ARP RARP IP SCTP TCP UDP ICMP IGMP IGRP PIM VRRP
%token  ATALK AARP DECNET LAT SCA MOPRC MOPDL
%token  TK_BROADCAST TK_MULTICAST
%token  NUM INBOUND OUTBOUND
%token  PF_IFNAME PF_RSET PF_RNR PF_SRNR PF_REASON PF_ACTION
%token  LINK
%token	GEQ LEQ NEQ
%token	ID EID HID HID6 AID
%token	LSH RSH
%token  LEN
%token  IPV6 ICMPV6 AH ESP
%token	VLAN MPLS
%token	PPPOED PPPOES
%token  ISO ESIS CLNP ISIS L1 L2 IIH LSP SNP CSNP PSNP 
%token  STP
%token  IPX
%token  NETBEUI
%token	LANE LLC METAC BCC SC ILMIC OAMF4EC OAMF4SC
%token	OAM OAMF4 CONNECTMSG METACONNECT
%token	VPI VCI
%token	RADIO
%token  SIO OPC DPC SLS

%type	<s> ID
%type	<e> EID
%type	<e> AID
%type	<s> HID HID6
%type	<i> NUM action reason

%left OR AND
%nonassoc  '!'
%left '|'
%left '&'
%left LSH RSH
%left '+' '-'
%left '*' '/'
%nonassoc UMINUS
%%
prog:	  null expr
{
	finish_parse($2.b);
}
	| null
	;
null:	  /* null */		{ $$.q = qerr; }
	;
expr:	  term
	| expr and term		{ gen_and($1.b, $3.b); $$ = $3; }
	| expr and id		{ gen_and($1.b, $3.b); $$ = $3; }
	| expr or term		{ gen_or($1.b, $3.b); $$ = $3; }
	| expr or id		{ gen_or($1.b, $3.b); $$ = $3; }
	;
and:	  AND			{ $$ = $<blk>0; }
	;
or:	  OR			{ $$ = $<blk>0; }
	;
id:	  nid
	| pnum			{ $$.b = gen_ncode(NULL, (bpf_u_int32)$1,
						   $$.q = $<blk>0.q); }
	| paren pid ')'		{ $$ = $2; }
	;
nid:	  ID			{ $$.b = gen_scode($1, $$.q = $<blk>0.q); }
	| HID '/' NUM		{ $$.b = gen_mcode($1, NULL, $3,
				    $$.q = $<blk>0.q); }
	| HID NETMASK HID	{ $$.b = gen_mcode($1, $3, 0,
				    $$.q = $<blk>0.q); }
	| HID			{
				  /* Decide how to parse HID based on proto */
				  $$.q = $<blk>0.q;
				  $$.b = gen_ncode($1, 0, $$.q);
				}
	| HID6 '/' NUM		{
#ifdef INET6
				  $$.b = gen_mcode6($1, NULL, $3,
				    $$.q = $<blk>0.q);
#else
				  bpf_error("'ip6addr/prefixlen' not supported "
					"in this configuration");
#endif /*INET6*/
				}
	| HID6			{
#ifdef INET6
				  $$.b = gen_mcode6($1, 0, 128,
				    $$.q = $<blk>0.q);
#else
				  bpf_error("'ip6addr' not supported "
					"in this configuration");
#endif /*INET6*/
				}
	| EID			{ 
				  $$.b = gen_ecode($1, $$.q = $<blk>0.q);
				  /*
				   * $1 was allocated by "pcap_ether_aton()",
				   * so we must free it now that we're done
				   * with it.
				   */
				  free($1);
				}
	| AID			{
				  $$.b = gen_acode($1, $$.q = $<blk>0.q);
				  /*
				   * $1 was allocated by "pcap_ether_aton()",
				   * so we must free it now that we're done
				   * with it.
				   */
				  free($1);
				}
	| not id		{ gen_not($2.b); $$ = $2; }
	;
not:	  '!'			{ $$ = $<blk>0; }
	;
paren:	  '('			{ $$ = $<blk>0; }
	;
pid:	  nid
	| qid and id		{ gen_and($1.b, $3.b); $$ = $3; }
	| qid or id		{ gen_or($1.b, $3.b); $$ = $3; }
	;
qid:	  pnum			{ $$.b = gen_ncode(NULL, (bpf_u_int32)$1,
						   $$.q = $<blk>0.q); }
	| pid
	;
term:	  rterm
	| not term		{ gen_not($2.b); $$ = $2; }
	;
head:	  pqual dqual aqual	{ QSET($$.q, $1, $2, $3); }
	| pqual dqual		{ QSET($$.q, $1, $2, Q_DEFAULT); }
	| pqual aqual		{ QSET($$.q, $1, Q_DEFAULT, $2); }
	| pqual PROTO		{ QSET($$.q, $1, Q_DEFAULT, Q_PROTO); }
	| pqual PROTOCHAIN	{ QSET($$.q, $1, Q_DEFAULT, Q_PROTOCHAIN); }
	| pqual ndaqual		{ QSET($$.q, $1, Q_DEFAULT, $2); }
	;
rterm:	  head id		{ $$ = $2; }
	| paren expr ')'	{ $$.b = $2.b; $$.q = $1.q; }
	| pname			{ $$.b = gen_proto_abbrev($1); $$.q = qerr; }
	| arth relop arth	{ $$.b = gen_relation($2, $1, $3, 0);
				  $$.q = qerr; }
	| arth irelop arth	{ $$.b = gen_relation($2, $1, $3, 1);
				  $$.q = qerr; }
	| other			{ $$.b = $1; $$.q = qerr; }
	| atmtype		{ $$.b = gen_atmtype_abbrev($1); $$.q = qerr; }
	| atmmultitype		{ $$.b = gen_atmmulti_abbrev($1); $$.q = qerr; }
	| atmfield atmvalue	{ $$.b = $2.b; $$.q = qerr; }
	| mtp3field mtp3value	{ $$.b = $2.b; $$.q = qerr; }
	;
/* protocol level qualifiers */
pqual:	  pname
	|			{ $$ = Q_DEFAULT; }
	;
/* 'direction' qualifiers */
dqual:	  SRC			{ $$ = Q_SRC; }
	| DST			{ $$ = Q_DST; }
	| SRC OR DST		{ $$ = Q_OR; }
	| DST OR SRC		{ $$ = Q_OR; }
	| SRC AND DST		{ $$ = Q_AND; }
	| DST AND SRC		{ $$ = Q_AND; }
	;
/* address type qualifiers */
aqual:	  HOST			{ $$ = Q_HOST; }
	| NET			{ $$ = Q_NET; }
	| PORT			{ $$ = Q_PORT; }
	| PORTRANGE		{ $$ = Q_PORTRANGE; }
	;
/* non-directional address type qualifiers */
ndaqual:  GATEWAY		{ $$ = Q_GATEWAY; }
	;
pname:	  LINK			{ $$ = Q_LINK; }
	| IP			{ $$ = Q_IP; }
	| ARP			{ $$ = Q_ARP; }
	| RARP			{ $$ = Q_RARP; }
	| SCTP			{ $$ = Q_SCTP; }
	| TCP			{ $$ = Q_TCP; }
	| UDP			{ $$ = Q_UDP; }
	| ICMP			{ $$ = Q_ICMP; }
	| IGMP			{ $$ = Q_IGMP; }
	| IGRP			{ $$ = Q_IGRP; }
	| PIM			{ $$ = Q_PIM; }
	| VRRP			{ $$ = Q_VRRP; }
	| ATALK			{ $$ = Q_ATALK; }
	| AARP			{ $$ = Q_AARP; }
	| DECNET		{ $$ = Q_DECNET; }
	| LAT			{ $$ = Q_LAT; }
	| SCA			{ $$ = Q_SCA; }
	| MOPDL			{ $$ = Q_MOPDL; }
	| MOPRC			{ $$ = Q_MOPRC; }
	| IPV6			{ $$ = Q_IPV6; }
	| ICMPV6		{ $$ = Q_ICMPV6; }
	| AH			{ $$ = Q_AH; }
	| ESP			{ $$ = Q_ESP; }
	| ISO			{ $$ = Q_ISO; }
	| ESIS			{ $$ = Q_ESIS; }
	| ISIS			{ $$ = Q_ISIS; }
	| L1			{ $$ = Q_ISIS_L1; }
	| L2			{ $$ = Q_ISIS_L2; }
	| IIH			{ $$ = Q_ISIS_IIH; }
	| LSP			{ $$ = Q_ISIS_LSP; }
	| SNP			{ $$ = Q_ISIS_SNP; }
	| PSNP			{ $$ = Q_ISIS_PSNP; }
	| CSNP			{ $$ = Q_ISIS_CSNP; }
	| CLNP			{ $$ = Q_CLNP; }
	| STP			{ $$ = Q_STP; }
	| IPX			{ $$ = Q_IPX; }
	| NETBEUI		{ $$ = Q_NETBEUI; }
	| RADIO			{ $$ = Q_RADIO; }
	;
other:	  pqual TK_BROADCAST	{ $$ = gen_broadcast($1); }
	| pqual TK_MULTICAST	{ $$ = gen_multicast($1); }
	| LESS NUM		{ $$ = gen_less($2); }
	| GREATER NUM		{ $$ = gen_greater($2); }
	| CBYTE NUM byteop NUM	{ $$ = gen_byteop($3, $2, $4); }
	| INBOUND		{ $$ = gen_inbound(0); }
	| OUTBOUND		{ $$ = gen_inbound(1); }
	| VLAN pnum		{ $$ = gen_vlan($2); }
	| VLAN			{ $$ = gen_vlan(-1); }
	| MPLS pnum		{ $$ = gen_mpls($2); }
	| MPLS			{ $$ = gen_mpls(-1); }
	| PPPOED		{ $$ = gen_pppoed(); }
	| PPPOES		{ $$ = gen_pppoes(); }
	| pfvar			{ $$ = $1; }
	;

pfvar:	  PF_IFNAME ID		{ $$ = gen_pf_ifname($2); }
	| PF_RSET ID		{ $$ = gen_pf_ruleset($2); }
	| PF_RNR NUM		{ $$ = gen_pf_rnr($2); }
	| PF_SRNR NUM		{ $$ = gen_pf_srnr($2); }
	| PF_REASON reason	{ $$ = gen_pf_reason($2); }
	| PF_ACTION action	{ $$ = gen_pf_action($2); }
	;

reason:	  NUM			{ $$ = $1; }
	| ID			{ const char *reasons[] = PFRES_NAMES;
				  int i;
				  for (i = 0; reasons[i]; i++) {
					  if (pcap_strcasecmp($1, reasons[i]) == 0) {
						  $$ = i;
						  break;
					  }
				  }
				  if (reasons[i] == NULL)
					  bpf_error("unknown PF reason");
				}
	;

action:	  ID			{ if (pcap_strcasecmp($1, "pass") == 0 ||
				      pcap_strcasecmp($1, "accept") == 0)
					$$ = PF_PASS;
				  else if (pcap_strcasecmp($1, "drop") == 0 ||
				      pcap_strcasecmp($1, "block") == 0)
					$$ = PF_DROP;
				  else
					  bpf_error("unknown PF action");
				}
	;

relop:	  '>'			{ $$ = BPF_JGT; }
	| GEQ			{ $$ = BPF_JGE; }
	| '='			{ $$ = BPF_JEQ; }
	;
irelop:	  LEQ			{ $$ = BPF_JGT; }
	| '<'			{ $$ = BPF_JGE; }
	| NEQ			{ $$ = BPF_JEQ; }
	;
arth:	  pnum			{ $$ = gen_loadi($1); }
	| narth
	;
narth:	  pname '[' arth ']'		{ $$ = gen_load($1, $3, 1); }
	| pname '[' arth ':' NUM ']'	{ $$ = gen_load($1, $3, $5); }
	| arth '+' arth			{ $$ = gen_arth(BPF_ADD, $1, $3); }
	| arth '-' arth			{ $$ = gen_arth(BPF_SUB, $1, $3); }
	| arth '*' arth			{ $$ = gen_arth(BPF_MUL, $1, $3); }
	| arth '/' arth			{ $$ = gen_arth(BPF_DIV, $1, $3); }
	| arth '&' arth			{ $$ = gen_arth(BPF_AND, $1, $3); }
	| arth '|' arth			{ $$ = gen_arth(BPF_OR, $1, $3); }
	| arth LSH arth			{ $$ = gen_arth(BPF_LSH, $1, $3); }
	| arth RSH arth			{ $$ = gen_arth(BPF_RSH, $1, $3); }
	| '-' arth %prec UMINUS		{ $$ = gen_neg($2); }
	| paren narth ')'		{ $$ = $2; }
	| LEN				{ $$ = gen_loadlen(); }
	;
byteop:	  '&'			{ $$ = '&'; }
	| '|'			{ $$ = '|'; }
	| '<'			{ $$ = '<'; }
	| '>'			{ $$ = '>'; }
	| '='			{ $$ = '='; }
	;
pnum:	  NUM
	| paren pnum ')'	{ $$ = $2; }
	;
atmtype: LANE			{ $$ = A_LANE; }
	| LLC			{ $$ = A_LLC; }
	| METAC			{ $$ = A_METAC;	}
	| BCC			{ $$ = A_BCC; }
	| OAMF4EC		{ $$ = A_OAMF4EC; }
	| OAMF4SC		{ $$ = A_OAMF4SC; }
	| SC			{ $$ = A_SC; }
	| ILMIC			{ $$ = A_ILMIC; }
	;
atmmultitype: OAM		{ $$ = A_OAM; }
	| OAMF4			{ $$ = A_OAMF4; }
	| CONNECTMSG		{ $$ = A_CONNECTMSG; }
	| METACONNECT		{ $$ = A_METACONNECT; }
	;
	/* ATM field types quantifier */
atmfield: VPI			{ $$.atmfieldtype = A_VPI; }
	| VCI			{ $$.atmfieldtype = A_VCI; }
	;
atmvalue: atmfieldvalue
	| relop NUM		{ $$.b = gen_atmfield_code($<blk>0.atmfieldtype, (bpf_int32)$2, (bpf_u_int32)$1, 0); }
	| irelop NUM		{ $$.b = gen_atmfield_code($<blk>0.atmfieldtype, (bpf_int32)$2, (bpf_u_int32)$1, 1); }
	| paren atmlistvalue ')' { $$.b = $2.b; $$.q = qerr; }
	;
atmfieldvalue: NUM {
	$$.atmfieldtype = $<blk>0.atmfieldtype;
	if ($$.atmfieldtype == A_VPI ||
	    $$.atmfieldtype == A_VCI)
		$$.b = gen_atmfield_code($$.atmfieldtype, (bpf_int32) $1, BPF_JEQ, 0);
	}
	;
atmlistvalue: atmfieldvalue
	| atmlistvalue or atmfieldvalue { gen_or($1.b, $3.b); $$ = $3; }
	;
	/* MTP3 field types quantifier */
mtp3field: SIO			{ $$.mtp3fieldtype = M_SIO; }
	| OPC			{ $$.mtp3fieldtype = M_OPC; }
	| DPC			{ $$.mtp3fieldtype = M_DPC; }
	| SLS                   { $$.mtp3fieldtype = M_SLS; }
	;
mtp3value: mtp3fieldvalue
	| relop NUM		{ $$.b = gen_mtp3field_code($<blk>0.mtp3fieldtype, (u_int)$2, (u_int)$1, 0); }
	| irelop NUM		{ $$.b = gen_mtp3field_code($<blk>0.mtp3fieldtype, (u_int)$2, (u_int)$1, 1); }
	| paren mtp3listvalue ')' { $$.b = $2.b; $$.q = qerr; }
	;
mtp3fieldvalue: NUM {
	$$.mtp3fieldtype = $<blk>0.mtp3fieldtype;
	if ($$.mtp3fieldtype == M_SIO ||
	    $$.mtp3fieldtype == M_OPC ||
	    $$.mtp3fieldtype == M_DPC ||
	    $$.mtp3fieldtype == M_SLS )
		$$.b = gen_mtp3field_code($$.mtp3fieldtype, (u_int) $1, BPF_JEQ, 0);
	}
	;
mtp3listvalue: mtp3fieldvalue
	| mtp3listvalue or mtp3fieldvalue { gen_or($1.b, $3.b); $$ = $3; }
	;
%%
