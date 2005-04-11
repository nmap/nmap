#ifndef lint
static char const 
yyrcsid[] = "$FreeBSD: src/usr.bin/yacc/skeleton.c,v 1.28 2000/01/17 02:04:06 bde Exp $";
#endif
#include <stdlib.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
static int yygrowstack();
#define YYPREFIX "yy"
#line 2 "grammar.y"
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
    "@(#) $Header$ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include <pcap-stdinc.h>
#else /* WIN32 */
#include <sys/types.h>
#include <sys/time.h>
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
#include <strings.h>

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

#line 92 "grammar.y"
typedef union {
	int i;
	bpf_u_int32 h;
	u_char *e;
	char *s;
	struct stmt *stmt;
	struct arth *a;
	struct {
		struct qual q;
		int atmfieldtype;
		struct block *b;
	} blk;
	struct block *rblk;
} YYSTYPE;
#line 121 "y.tab.c"
#define YYERRCODE 256
#define DST 257
#define SRC 258
#define HOST 259
#define GATEWAY 260
#define NET 261
#define NETMASK 262
#define PORT 263
#define LESS 264
#define GREATER 265
#define PROTO 266
#define PROTOCHAIN 267
#define CBYTE 268
#define ARP 269
#define RARP 270
#define IP 271
#define SCTP 272
#define TCP 273
#define UDP 274
#define ICMP 275
#define IGMP 276
#define IGRP 277
#define PIM 278
#define VRRP 279
#define ATALK 280
#define AARP 281
#define DECNET 282
#define LAT 283
#define SCA 284
#define MOPRC 285
#define MOPDL 286
#define TK_BROADCAST 287
#define TK_MULTICAST 288
#define NUM 289
#define INBOUND 290
#define OUTBOUND 291
#define PF_IFNAME 292
#define PF_RSET 293
#define PF_RNR 294
#define PF_SRNR 295
#define PF_REASON 296
#define PF_ACTION 297
#define LINK 298
#define GEQ 299
#define LEQ 300
#define NEQ 301
#define ID 302
#define EID 303
#define HID 304
#define HID6 305
#define AID 306
#define LSH 307
#define RSH 308
#define LEN 309
#define IPV6 310
#define ICMPV6 311
#define AH 312
#define ESP 313
#define VLAN 314
#define ISO 315
#define ESIS 316
#define CLNP 317
#define ISIS 318
#define L1 319
#define L2 320
#define IIH 321
#define LSP 322
#define SNP 323
#define CSNP 324
#define PSNP 325
#define STP 326
#define IPX 327
#define NETBEUI 328
#define LANE 329
#define LLC 330
#define METAC 331
#define BCC 332
#define SC 333
#define ILMIC 334
#define OAMF4EC 335
#define OAMF4SC 336
#define OAM 337
#define OAMF4 338
#define CONNECTMSG 339
#define METACONNECT 340
#define VPI 341
#define VCI 342
#define OR 343
#define AND 344
#define UMINUS 345
const short yylhs[] = {                                        -1,
    0,    0,   24,    1,    1,    1,    1,    1,   20,   21,
    2,    2,    2,    3,    3,    3,    3,    3,    3,    3,
    3,    3,   23,   22,    4,    4,    4,    7,    7,    5,
    5,    8,    8,    8,    8,    8,    8,    6,    6,    6,
    6,    6,    6,    6,    6,    6,    9,    9,   10,   10,
   10,   10,   10,   10,   11,   11,   11,   12,   16,   16,
   16,   16,   16,   16,   16,   16,   16,   16,   16,   16,
   16,   16,   16,   16,   16,   16,   16,   16,   16,   16,
   16,   16,   16,   16,   16,   16,   16,   16,   16,   16,
   16,   16,   16,   16,   16,   25,   25,   25,   25,   25,
   25,   25,   25,   25,   25,   26,   26,   26,   26,   26,
   26,   34,   34,   33,   18,   18,   18,   19,   19,   19,
   13,   13,   14,   14,   14,   14,   14,   14,   14,   14,
   14,   14,   14,   14,   14,   15,   15,   15,   15,   15,
   17,   17,   27,   27,   27,   27,   27,   27,   27,   27,
   28,   28,   28,   28,   29,   29,   31,   31,   31,   31,
   30,   32,   32,
};
const short yylen[] = {                                         2,
    2,    1,    0,    1,    3,    3,    3,    3,    1,    1,
    1,    1,    3,    1,    3,    3,    1,    3,    1,    1,
    1,    2,    1,    1,    1,    3,    3,    1,    1,    1,
    2,    3,    2,    2,    2,    2,    2,    2,    3,    1,
    3,    3,    1,    1,    1,    2,    1,    0,    1,    1,
    3,    3,    3,    3,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    2,    2,    2,    2,    4,
    1,    1,    2,    1,    1,    2,    2,    2,    2,    2,
    2,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    4,    6,    3,    3,    3,    3,    3,    3,
    3,    3,    2,    3,    1,    1,    1,    1,    1,    1,
    1,    3,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    2,    2,    3,
    1,    1,    3,
};
const short yydefred[] = {                                      3,
    0,    0,    0,    0,    0,   61,   62,   60,   63,   64,
   65,   66,   67,   68,   69,   70,   71,   72,   73,   74,
   75,   77,   76,  141,  101,  102,    0,    0,    0,    0,
    0,    0,   59,  135,   78,   79,   80,   81,    0,   82,
   83,   92,   84,   85,   86,   87,   88,   89,   91,   90,
   93,   94,   95,  143,  144,  145,  146,  149,  150,  147,
  148,  151,  152,  153,  154,  155,  156,   23,    0,   24,
    0,    4,   30,    0,    0,    0,  122,    0,  121,    0,
    0,   43,  105,   44,   45,    0,   98,   99,    0,  106,
  107,  108,  109,  112,  113,  110,  114,  111,  103,    0,
  133,    0,    0,   10,    9,    0,    0,   14,   20,    0,
    0,   21,   38,   11,   12,    0,    0,    0,    0,   55,
   58,   56,   57,   35,   36,   96,   97,    0,   34,   37,
  116,  118,  120,    0,    0,    0,    0,    0,    0,    0,
    0,  115,  117,  119,    0,    0,    0,    0,    0,    0,
   31,  161,    0,    0,    0,  157,   46,  137,  136,  139,
  140,  138,    0,    0,    0,    6,    5,    0,    0,    0,
    8,    7,    0,    0,    0,   25,    0,    0,    0,   22,
    0,    0,    0,    0,   32,    0,    0,    0,    0,    0,
    0,  127,  128,    0,    0,    0,   39,  134,  142,  158,
  159,  162,    0,  100,    0,   16,   15,   18,   13,    0,
    0,   52,   54,   51,   53,  123,    0,  160,    0,   26,
   27,    0,  163,  124,
};
const short yydgoto[] = {                                       1,
  148,  180,  114,  177,   72,   73,  178,   74,   75,  128,
  129,  130,   76,   77,  163,  102,   79,  145,  146,  106,
  107,  103,  117,    2,   82,   83,   84,   85,   86,  156,
  157,  203,   98,   96,
};
const short yysindex[] = {                                      0,
    0,  246, -276, -268, -262,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0, -271, -261, -244, -242,
 -280, -252,    0,    0,    0,    0,    0,    0,  -35,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  345,    0,
 -320,    0,    0,   99, -106,  551,    0,  -36,    0,  246,
  246,    0,    0,    0,    0,  346,    0,    0,   61,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  -35,
    0,  -36,  345,    0,    0,  153,  153,    0,    0,  -45,
   10,    0,    0,    0,    0,   99,   99, -238, -228,    0,
    0,    0,    0,    0,    0,    0,    0, -168,    0,    0,
    0,    0,    0,  345,  345,  345,  345,  345,  345,  345,
  345,    0,    0,    0,  345,  345,  345,  -37,   24,   27,
    0,    0, -209, -207, -199,    0,    0,    0,    0,    0,
    0,    0, -193,   27,  189,    0,    0,    0,  153,  153,
    0,    0, -229, -179, -171,    0,   79, -320,   27,    0,
 -127, -111, -109, -101,    0,  -27,  -27,  195,  245,  -12,
  -12,    0,    0,  189,  189,  595,    0,    0,    0,    0,
    0,    0,  -29,    0,   27,    0,    0,    0,    0,   99,
   99,    0,    0,    0,    0,    0, -131,    0, -199,    0,
    0,   69,    0,    0,
};
const short yyrindex[] = {                                      0,
    0,  440,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   19,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  163,    0,    0,    0,    0,    0,    0,   17,    0,  526,
  526,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  526,  526,    0,    0,   29,
   36,    0,    0,    0,    0,    0,    0,  -33,   -8,    0,
    0,    0,    0,    0,    0,    0,    0,  109,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  648,  673,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    1,  526,  526,
    0,    0,    0,    0,    0,    0, -214,    0, -198,    0,
    0,    0,    0,    0,    0,   26,   51,   66,   76,   11,
   40,    0,    0,   38,   53,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  205,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,
};
const short yygindex[] = {                                      0,
  164,   34, -110,    0,  -73,    0,    0,    0,    0,    0,
   37,    0,   74,  -66,    0,  657,  674,   81,   82,   -7,
 -175,  650,  672,    0,    0,    0,    0,    0,    0, -145,
    0,    0,    0,    0,
};
#define YYTABLESIZE 981
const short yytable[] = {                                      50,
   12,  174,  211,  197,   70,  176,   50,  151,   94,  202,
  125,  218,   87,  149,  140,  138,   40,  139,  104,  141,
   88,   95,  104,  105,   49,  131,   89,  219,   17,  140,
   90,   49,  167,  172,  141,   19,  149,   41,  121,  126,
   91,   12,  121,  121,   92,  121,   93,  121,  125,   97,
  132,  125,   42,  125,  147,  125,  175,   40,  176,  104,
  121,  121,  121,  131,  198,  130,  131,  199,  125,   17,
  125,  125,  125,  223,  206,  129,   19,  126,   41,  200,
  126,  201,  126,  131,  126,  131,  131,  131,  132,  152,
  120,  132,  122,   42,  123,  204,  151,  126,  159,  126,
  126,  126,  149,  125,  181,  182,  130,  113,  132,  207,
  132,  132,  132,  129,  183,  184,  129,  208,  131,  209,
  162,  161,  160,  130,  121,  130,  130,  130,   29,   29,
  212,   68,  126,  129,  125,  129,  129,  129,   70,  166,
  171,   33,  101,  132,   28,   28,  213,  214,   33,  131,
  118,  119,  120,  121,  122,  215,  123,  222,  130,  124,
  125,  224,    1,  126,  185,   71,  153,  154,  129,    0,
  210,    0,    0,    0,  132,    0,  165,    0,    0,    0,
  126,  127,    0,    0,  158,   68,    0,    0,    0,  130,
    0,    0,   70,    0,    0,    0,    0,   69,    0,  129,
    0,    0,    0,    0,    0,    0,    0,  186,  187,  188,
  189,  190,  191,  192,  193,    0,  173,    0,  194,  195,
  196,    0,    0,    0,    0,   50,  137,   50,    0,   50,
  140,  138,  137,  139,    0,  141,  140,  138,    0,  139,
    0,  141,  121,  220,  221,    0,  121,  121,    0,  121,
   49,  121,   49,   24,   49,   50,    0,    0,    0,    0,
    0,    0,    0,    0,  121,  121,  121,    0,   50,   50,
   50,   50,   50,   47,   47,   47,   47,   47,   68,   47,
   49,    0,   47,   47,    0,   70,  140,  138,    0,  139,
   69,  141,    0,   49,   49,   49,   49,   49,    0,  121,
  121,  121,    0,   47,   47,  104,  105,  121,  121,  125,
  125,  125,  136,  104,    0,    0,    0,  125,  125,    0,
    0,    0,    0,    0,  131,  131,  131,    0,  121,    0,
    0,    0,  131,  131,    0,    0,    0,    0,  126,  126,
  126,    0,    0,   12,   12,    0,  126,  126,    0,  132,
  132,  132,    0,  125,  125,    0,    0,  132,  132,   40,
   40,  104,  104,    0,  130,  130,  130,    0,  131,  131,
    0,   17,   17,    0,  129,  129,  129,    0,   19,   19,
   41,   41,  126,  126,   70,   70,    0,   24,    0,   69,
    0,    0,    0,  132,  132,   42,   42,   33,    0,    0,
  108,  109,  110,  111,  112,  144,  143,  142,  130,  130,
   33,   33,   33,   33,   33,    0,    3,    4,  129,  129,
    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,
   15,   16,   17,   18,   19,   20,   21,   22,   23,    2,
    0,   24,   25,   26,   27,   28,   29,   30,   31,   32,
   33,    0,    0,    0,  108,  109,  110,  111,  112,    0,
    0,   34,   35,   36,   37,   38,   39,   40,   41,   42,
   43,   44,   45,   46,   47,   48,   49,   50,   51,   52,
   53,   54,   55,   56,   57,   58,   59,   60,   61,   62,
   63,   64,   65,   66,   67,  134,  135,    0,    0,    0,
    0,  134,  135,  121,  121,  121,    0,    0,    0,    3,
    4,  121,  121,    5,    6,    7,    8,    9,   10,   11,
   12,   13,   14,   15,   16,   17,   18,   19,   20,   21,
   22,   23,    0,    0,   24,   25,   26,   27,   28,   29,
   30,   31,   32,   33,    0,    0,    0,   28,   28,    0,
    0,  134,  135,    0,   34,   35,   36,   37,   38,   39,
   40,   41,   42,   43,   44,   45,   46,   47,   48,   49,
   50,   51,   52,   53,   54,   55,   56,   57,   58,   59,
   60,   61,   62,   63,   64,   65,   66,   67,  137,    0,
    0,    0,  140,  138,    0,  139,    0,  141,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  144,  143,  142,    6,    7,    8,    9,   10,   11,   12,
   13,   14,   15,   16,   17,   18,   19,   20,   21,   22,
   23,    0,  137,   24,  152,    0,  140,  138,    0,  139,
    0,  141,   33,    0,  131,  132,  133,    0,    0,    0,
    0,   80,  217,   34,   35,   36,   37,   38,   78,   40,
   41,   42,   43,   44,   45,   46,   47,   48,   49,   50,
   51,   52,   53,   81,  136,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  122,    0,  216,  100,  122,
  122,    0,  122,    0,  122,    0,   48,   48,   48,   48,
   48,    0,   48,    0,    0,   48,   48,  122,  122,  122,
  121,    0,   99,    0,  121,  121,    0,  121,  136,  121,
    0,    0,    0,  116,    0,    0,   48,   48,    0,   80,
   80,    0,  121,  121,  121,  155,   78,   78,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  115,    0,  100,
    0,   81,   81,  150,    0,  169,  169,    0,    0,    0,
    0,    0,   78,   78,    0,  100,  116,    0,    0,    0,
    0,  122,    0,  164,    0,    0,  150,  170,  170,  168,
  168,    0,   48,   48,   48,   48,   48,    0,   48,  179,
  115,   48,   48,    0,    0,    0,  121,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   48,   48,    0,    0,    0,    0,   80,  169,
    0,    0,    0,    0,    0,   78,   78,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  170,  170,  205,  168,    0,    0,    0,    0,    0,  131,
  132,  133,    0,    0,    0,    0,    0,  134,  135,  116,
  116,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  115,  115,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  134,  135,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  122,  122,  122,    0,
    0,    0,    0,    0,  122,  122,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  121,  121,  121,    0,    0,    0,    0,    0,  121,
  121,
};
const short yycheck[] = {                                      33,
    0,   47,  178,   41,   40,  116,   40,   81,  289,  155,
    0,   41,  289,   80,   42,   43,    0,   45,    0,   47,
  289,  302,  343,  344,   33,    0,  289,  203,    0,   42,
  302,   40,  106,  107,   47,    0,  103,    0,   38,    0,
  302,   41,   42,   43,  289,   45,  289,   47,   38,  302,
    0,   41,    0,   43,   91,   45,   47,   41,  169,   41,
   60,   61,   62,   38,   41,    0,   41,   41,   58,   41,
   60,   61,   62,  219,  304,    0,   41,   38,   41,  289,
   41,  289,   43,   58,   45,   60,   61,   62,   38,  289,
  259,   41,  261,   41,  263,  289,  170,   58,   38,   60,
   61,   62,  169,   93,  343,  344,   41,   74,   58,  289,
   60,   61,   62,   38,  343,  344,   41,  289,   93,   41,
   60,   61,   62,   58,  124,   60,   61,   62,  343,  344,
  258,   33,   93,   58,  124,   60,   61,   62,   40,  106,
  107,   33,   69,   93,  343,  344,  258,  257,   40,  124,
  257,  258,  259,  260,  261,  257,  263,  289,   93,  266,
  267,   93,    0,  124,  128,    2,   86,   86,   93,   -1,
  178,   -1,   -1,   -1,  124,   -1,  103,   -1,   -1,   -1,
  287,  288,   -1,   -1,  124,   33,   -1,   -1,   -1,  124,
   -1,   -1,   40,   -1,   -1,   -1,   -1,   45,   -1,  124,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  134,  135,  136,
  137,  138,  139,  140,  141,   -1,  262,   -1,  145,  146,
  147,   -1,   -1,   -1,   -1,  259,   38,  261,   -1,  263,
   42,   43,   38,   45,   -1,   47,   42,   43,   -1,   45,
   -1,   47,   38,  210,  211,   -1,   42,   43,   -1,   45,
  259,   47,  261,  289,  263,  289,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   60,   61,   62,   -1,  302,  303,
  304,  305,  306,  257,  258,  259,  260,  261,   33,  263,
  289,   -1,  266,  267,   -1,   40,   42,   43,   -1,   45,
   45,   47,   -1,  302,  303,  304,  305,  306,   -1,  299,
  300,  301,   -1,  287,  288,  343,  344,  307,  308,  299,
  300,  301,  124,  343,   -1,   -1,   -1,  307,  308,   -1,
   -1,   -1,   -1,   -1,  299,  300,  301,   -1,  124,   -1,
   -1,   -1,  307,  308,   -1,   -1,   -1,   -1,  299,  300,
  301,   -1,   -1,  343,  344,   -1,  307,  308,   -1,  299,
  300,  301,   -1,  343,  344,   -1,   -1,  307,  308,  343,
  344,  343,  344,   -1,  299,  300,  301,   -1,  343,  344,
   -1,  343,  344,   -1,  299,  300,  301,   -1,  343,  344,
  343,  344,  343,  344,   40,   40,   -1,  289,   -1,   45,
   -1,   -1,   -1,  343,  344,  343,  344,  289,   -1,   -1,
  302,  303,  304,  305,  306,   60,   61,   62,  343,  344,
  302,  303,  304,  305,  306,   -1,  264,  265,  343,  344,
  268,  269,  270,  271,  272,  273,  274,  275,  276,  277,
  278,  279,  280,  281,  282,  283,  284,  285,  286,    0,
   -1,  289,  290,  291,  292,  293,  294,  295,  296,  297,
  298,   -1,   -1,   -1,  302,  303,  304,  305,  306,   -1,
   -1,  309,  310,  311,  312,  313,  314,  315,  316,  317,
  318,  319,  320,  321,  322,  323,  324,  325,  326,  327,
  328,  329,  330,  331,  332,  333,  334,  335,  336,  337,
  338,  339,  340,  341,  342,  307,  308,   -1,   -1,   -1,
   -1,  307,  308,  299,  300,  301,   -1,   -1,   -1,  264,
  265,  307,  308,  268,  269,  270,  271,  272,  273,  274,
  275,  276,  277,  278,  279,  280,  281,  282,  283,  284,
  285,  286,   -1,   -1,  289,  290,  291,  292,  293,  294,
  295,  296,  297,  298,   -1,   -1,   -1,  343,  344,   -1,
   -1,  307,  308,   -1,  309,  310,  311,  312,  313,  314,
  315,  316,  317,  318,  319,  320,  321,  322,  323,  324,
  325,  326,  327,  328,  329,  330,  331,  332,  333,  334,
  335,  336,  337,  338,  339,  340,  341,  342,   38,   -1,
   -1,   -1,   42,   43,   -1,   45,   -1,   47,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   60,   61,   62,  269,  270,  271,  272,  273,  274,  275,
  276,  277,  278,  279,  280,  281,  282,  283,  284,  285,
  286,   -1,   38,  289,  289,   -1,   42,   43,   -1,   45,
   -1,   47,  298,   -1,  299,  300,  301,   -1,   -1,   -1,
   -1,    2,   58,  309,  310,  311,  312,  313,    2,  315,
  316,  317,  318,  319,  320,  321,  322,  323,  324,  325,
  326,  327,  328,    2,  124,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   38,   -1,   93,   39,   42,
   43,   -1,   45,   -1,   47,   -1,  257,  258,  259,  260,
  261,   -1,  263,   -1,   -1,  266,  267,   60,   61,   62,
   38,   -1,   39,   -1,   42,   43,   -1,   45,  124,   47,
   -1,   -1,   -1,   74,   -1,   -1,  287,  288,   -1,   80,
   81,   -1,   60,   61,   62,   86,   80,   81,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   74,   -1,  100,
   -1,   80,   81,   80,   -1,  106,  107,   -1,   -1,   -1,
   -1,   -1,  106,  107,   -1,  116,  117,   -1,   -1,   -1,
   -1,  124,   -1,  100,   -1,   -1,  103,  106,  107,  106,
  107,   -1,  257,  258,  259,  260,  261,   -1,  263,  116,
  117,  266,  267,   -1,   -1,   -1,  124,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  287,  288,   -1,   -1,   -1,   -1,  169,  170,
   -1,   -1,   -1,   -1,   -1,  169,  170,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  169,  170,  169,  170,   -1,   -1,   -1,   -1,   -1,  299,
  300,  301,   -1,   -1,   -1,   -1,   -1,  307,  308,  210,
  211,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  210,  211,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  307,  308,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  299,  300,  301,   -1,
   -1,   -1,   -1,   -1,  307,  308,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  299,  300,  301,   -1,   -1,   -1,   -1,   -1,  307,
  308,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 345
#if YYDEBUG
const char * const yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,0,"'&'",0,"'('","')'","'*'","'+'",0,"'-'",0,"'/'",0,0,0,0,0,0,0,0,0,
0,"':'",0,"'<'","'='","'>'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,"'['",0,"']'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'|'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"DST","SRC","HOST","GATEWAY","NET","NETMASK",
"PORT","LESS","GREATER","PROTO","PROTOCHAIN","CBYTE","ARP","RARP","IP","SCTP",
"TCP","UDP","ICMP","IGMP","IGRP","PIM","VRRP","ATALK","AARP","DECNET","LAT",
"SCA","MOPRC","MOPDL","TK_BROADCAST","TK_MULTICAST","NUM","INBOUND","OUTBOUND",
"PF_IFNAME","PF_RSET","PF_RNR","PF_SRNR","PF_REASON","PF_ACTION","LINK","GEQ",
"LEQ","NEQ","ID","EID","HID","HID6","AID","LSH","RSH","LEN","IPV6","ICMPV6",
"AH","ESP","VLAN","ISO","ESIS","CLNP","ISIS","L1","L2","IIH","LSP","SNP","CSNP",
"PSNP","STP","IPX","NETBEUI","LANE","LLC","METAC","BCC","SC","ILMIC","OAMF4EC",
"OAMF4SC","OAM","OAMF4","CONNECTMSG","METACONNECT","VPI","VCI","OR","AND",
"UMINUS",
};
const char * const yyrule[] = {
"$accept : prog",
"prog : null expr",
"prog : null",
"null :",
"expr : term",
"expr : expr and term",
"expr : expr and id",
"expr : expr or term",
"expr : expr or id",
"and : AND",
"or : OR",
"id : nid",
"id : pnum",
"id : paren pid ')'",
"nid : ID",
"nid : HID '/' NUM",
"nid : HID NETMASK HID",
"nid : HID",
"nid : HID6 '/' NUM",
"nid : HID6",
"nid : EID",
"nid : AID",
"nid : not id",
"not : '!'",
"paren : '('",
"pid : nid",
"pid : qid and id",
"pid : qid or id",
"qid : pnum",
"qid : pid",
"term : rterm",
"term : not term",
"head : pqual dqual aqual",
"head : pqual dqual",
"head : pqual aqual",
"head : pqual PROTO",
"head : pqual PROTOCHAIN",
"head : pqual ndaqual",
"rterm : head id",
"rterm : paren expr ')'",
"rterm : pname",
"rterm : arth relop arth",
"rterm : arth irelop arth",
"rterm : other",
"rterm : atmtype",
"rterm : atmmultitype",
"rterm : atmfield atmvalue",
"pqual : pname",
"pqual :",
"dqual : SRC",
"dqual : DST",
"dqual : SRC OR DST",
"dqual : DST OR SRC",
"dqual : SRC AND DST",
"dqual : DST AND SRC",
"aqual : HOST",
"aqual : NET",
"aqual : PORT",
"ndaqual : GATEWAY",
"pname : LINK",
"pname : IP",
"pname : ARP",
"pname : RARP",
"pname : SCTP",
"pname : TCP",
"pname : UDP",
"pname : ICMP",
"pname : IGMP",
"pname : IGRP",
"pname : PIM",
"pname : VRRP",
"pname : ATALK",
"pname : AARP",
"pname : DECNET",
"pname : LAT",
"pname : SCA",
"pname : MOPDL",
"pname : MOPRC",
"pname : IPV6",
"pname : ICMPV6",
"pname : AH",
"pname : ESP",
"pname : ISO",
"pname : ESIS",
"pname : ISIS",
"pname : L1",
"pname : L2",
"pname : IIH",
"pname : LSP",
"pname : SNP",
"pname : PSNP",
"pname : CSNP",
"pname : CLNP",
"pname : STP",
"pname : IPX",
"pname : NETBEUI",
"other : pqual TK_BROADCAST",
"other : pqual TK_MULTICAST",
"other : LESS NUM",
"other : GREATER NUM",
"other : CBYTE NUM byteop NUM",
"other : INBOUND",
"other : OUTBOUND",
"other : VLAN pnum",
"other : VLAN",
"other : pfvar",
"pfvar : PF_IFNAME ID",
"pfvar : PF_RSET ID",
"pfvar : PF_RNR NUM",
"pfvar : PF_SRNR NUM",
"pfvar : PF_REASON reason",
"pfvar : PF_ACTION action",
"reason : NUM",
"reason : ID",
"action : ID",
"relop : '>'",
"relop : GEQ",
"relop : '='",
"irelop : LEQ",
"irelop : '<'",
"irelop : NEQ",
"arth : pnum",
"arth : narth",
"narth : pname '[' arth ']'",
"narth : pname '[' arth ':' NUM ']'",
"narth : arth '+' arth",
"narth : arth '-' arth",
"narth : arth '*' arth",
"narth : arth '/' arth",
"narth : arth '&' arth",
"narth : arth '|' arth",
"narth : arth LSH arth",
"narth : arth RSH arth",
"narth : '-' arth",
"narth : paren narth ')'",
"narth : LEN",
"byteop : '&'",
"byteop : '|'",
"byteop : '<'",
"byteop : '>'",
"byteop : '='",
"pnum : NUM",
"pnum : paren pnum ')'",
"atmtype : LANE",
"atmtype : LLC",
"atmtype : METAC",
"atmtype : BCC",
"atmtype : OAMF4EC",
"atmtype : OAMF4SC",
"atmtype : SC",
"atmtype : ILMIC",
"atmmultitype : OAM",
"atmmultitype : OAMF4",
"atmmultitype : CONNECTMSG",
"atmmultitype : METACONNECT",
"atmfield : VPI",
"atmfield : VCI",
"atmvalue : atmfieldvalue",
"atmvalue : relop NUM",
"atmvalue : irelop NUM",
"atmvalue : paren atmlistvalue ')'",
"atmfieldvalue : NUM",
"atmlistvalue : atmfieldvalue",
"atmlistvalue : atmlistvalue or atmfieldvalue",
};
#endif
#if YYDEBUG
#include <stdio.h>
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
int yystacksize;
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack()
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    i = yyssp - yyss;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss);
    if (newss == NULL)
        return -1;
    yyss = newss;
    yyssp = newss + i;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs);
    if (newvs == NULL)
        return -1;
    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab

#ifndef YYPARSE_PARAM
#if defined(__cplusplus) || __STDC__
#define YYPARSE_PARAM_ARG void
#define YYPARSE_PARAM_DECL
#else	/* ! ANSI-C/C++ */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif	/* ANSI-C/C++ */
#else	/* YYPARSE_PARAM */
#ifndef YYPARSE_PARAM_TYPE
#define YYPARSE_PARAM_TYPE void *
#endif
#if defined(__cplusplus) || __STDC__
#define YYPARSE_PARAM_ARG YYPARSE_PARAM_TYPE YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else	/* ! ANSI-C/C++ */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL YYPARSE_PARAM_TYPE YYPARSE_PARAM;
#endif	/* ANSI-C/C++ */
#endif	/* ! YYPARSE_PARAM */

int
yyparse (YYPARSE_PARAM_ARG)
    YYPARSE_PARAM_DECL
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register const char *yys;

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate])) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#if defined(lint) || defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(lint) || defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 1:
#line 156 "grammar.y"
{
	finish_parse(yyvsp[0].blk.b);
}
break;
case 3:
#line 161 "grammar.y"
{ yyval.blk.q = qerr; }
break;
case 5:
#line 164 "grammar.y"
{ gen_and(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 6:
#line 165 "grammar.y"
{ gen_and(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 7:
#line 166 "grammar.y"
{ gen_or(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 8:
#line 167 "grammar.y"
{ gen_or(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 9:
#line 169 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 10:
#line 171 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 12:
#line 174 "grammar.y"
{ yyval.blk.b = gen_ncode(NULL, (bpf_u_int32)yyvsp[0].i,
						   yyval.blk.q = yyvsp[-1].blk.q); }
break;
case 13:
#line 176 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 14:
#line 178 "grammar.y"
{ yyval.blk.b = gen_scode(yyvsp[0].s, yyval.blk.q = yyvsp[-1].blk.q); }
break;
case 15:
#line 179 "grammar.y"
{ yyval.blk.b = gen_mcode(yyvsp[-2].s, NULL, yyvsp[0].i,
				    yyval.blk.q = yyvsp[-3].blk.q); }
break;
case 16:
#line 181 "grammar.y"
{ yyval.blk.b = gen_mcode(yyvsp[-2].s, yyvsp[0].s, 0,
				    yyval.blk.q = yyvsp[-3].blk.q); }
break;
case 17:
#line 183 "grammar.y"
{
				  /* Decide how to parse HID based on proto */
				  yyval.blk.q = yyvsp[-1].blk.q;
				  yyval.blk.b = gen_ncode(yyvsp[0].s, 0, yyval.blk.q);
				}
break;
case 18:
#line 188 "grammar.y"
{
#ifdef INET6
				  yyval.blk.b = gen_mcode6(yyvsp[-2].s, NULL, yyvsp[0].i,
				    yyval.blk.q = yyvsp[-3].blk.q);
#else
				  bpf_error("'ip6addr/prefixlen' not supported "
					"in this configuration");
#endif /*INET6*/
				}
break;
case 19:
#line 197 "grammar.y"
{
#ifdef INET6
				  yyval.blk.b = gen_mcode6(yyvsp[0].s, 0, 128,
				    yyval.blk.q = yyvsp[-1].blk.q);
#else
				  bpf_error("'ip6addr' not supported "
					"in this configuration");
#endif /*INET6*/
				}
break;
case 20:
#line 206 "grammar.y"
{ 
				  yyval.blk.b = gen_ecode(yyvsp[0].e, yyval.blk.q = yyvsp[-1].blk.q);
				  /*
				   * $1 was allocated by "pcap_ether_aton()",
				   * so we must free it now that we're done
				   * with it.
				   */
				  free(yyvsp[0].e);
				}
break;
case 21:
#line 215 "grammar.y"
{
				  yyval.blk.b = gen_acode(yyvsp[0].e, yyval.blk.q = yyvsp[-1].blk.q);
				  /*
				   * $1 was allocated by "pcap_ether_aton()",
				   * so we must free it now that we're done
				   * with it.
				   */
				  free(yyvsp[0].e);
				}
break;
case 22:
#line 224 "grammar.y"
{ gen_not(yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 23:
#line 226 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 24:
#line 228 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 26:
#line 231 "grammar.y"
{ gen_and(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 27:
#line 232 "grammar.y"
{ gen_or(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 28:
#line 234 "grammar.y"
{ yyval.blk.b = gen_ncode(NULL, (bpf_u_int32)yyvsp[0].i,
						   yyval.blk.q = yyvsp[-1].blk.q); }
break;
case 31:
#line 239 "grammar.y"
{ gen_not(yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 32:
#line 241 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-2].i, yyvsp[-1].i, yyvsp[0].i); }
break;
case 33:
#line 242 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, yyvsp[0].i, Q_DEFAULT); }
break;
case 34:
#line 243 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, Q_DEFAULT, yyvsp[0].i); }
break;
case 35:
#line 244 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, Q_DEFAULT, Q_PROTO); }
break;
case 36:
#line 245 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, Q_DEFAULT, Q_PROTOCHAIN); }
break;
case 37:
#line 246 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, Q_DEFAULT, yyvsp[0].i); }
break;
case 38:
#line 248 "grammar.y"
{ yyval.blk = yyvsp[0].blk; }
break;
case 39:
#line 249 "grammar.y"
{ yyval.blk.b = yyvsp[-1].blk.b; yyval.blk.q = yyvsp[-2].blk.q; }
break;
case 40:
#line 250 "grammar.y"
{ yyval.blk.b = gen_proto_abbrev(yyvsp[0].i); yyval.blk.q = qerr; }
break;
case 41:
#line 251 "grammar.y"
{ yyval.blk.b = gen_relation(yyvsp[-1].i, yyvsp[-2].a, yyvsp[0].a, 0);
				  yyval.blk.q = qerr; }
break;
case 42:
#line 253 "grammar.y"
{ yyval.blk.b = gen_relation(yyvsp[-1].i, yyvsp[-2].a, yyvsp[0].a, 1);
				  yyval.blk.q = qerr; }
break;
case 43:
#line 255 "grammar.y"
{ yyval.blk.b = yyvsp[0].rblk; yyval.blk.q = qerr; }
break;
case 44:
#line 256 "grammar.y"
{ yyval.blk.b = gen_atmtype_abbrev(yyvsp[0].i); yyval.blk.q = qerr; }
break;
case 45:
#line 257 "grammar.y"
{ yyval.blk.b = gen_atmmulti_abbrev(yyvsp[0].i); yyval.blk.q = qerr; }
break;
case 46:
#line 258 "grammar.y"
{ yyval.blk.b = yyvsp[0].blk.b; yyval.blk.q = qerr; }
break;
case 48:
#line 262 "grammar.y"
{ yyval.i = Q_DEFAULT; }
break;
case 49:
#line 265 "grammar.y"
{ yyval.i = Q_SRC; }
break;
case 50:
#line 266 "grammar.y"
{ yyval.i = Q_DST; }
break;
case 51:
#line 267 "grammar.y"
{ yyval.i = Q_OR; }
break;
case 52:
#line 268 "grammar.y"
{ yyval.i = Q_OR; }
break;
case 53:
#line 269 "grammar.y"
{ yyval.i = Q_AND; }
break;
case 54:
#line 270 "grammar.y"
{ yyval.i = Q_AND; }
break;
case 55:
#line 273 "grammar.y"
{ yyval.i = Q_HOST; }
break;
case 56:
#line 274 "grammar.y"
{ yyval.i = Q_NET; }
break;
case 57:
#line 275 "grammar.y"
{ yyval.i = Q_PORT; }
break;
case 58:
#line 278 "grammar.y"
{ yyval.i = Q_GATEWAY; }
break;
case 59:
#line 280 "grammar.y"
{ yyval.i = Q_LINK; }
break;
case 60:
#line 281 "grammar.y"
{ yyval.i = Q_IP; }
break;
case 61:
#line 282 "grammar.y"
{ yyval.i = Q_ARP; }
break;
case 62:
#line 283 "grammar.y"
{ yyval.i = Q_RARP; }
break;
case 63:
#line 284 "grammar.y"
{ yyval.i = Q_SCTP; }
break;
case 64:
#line 285 "grammar.y"
{ yyval.i = Q_TCP; }
break;
case 65:
#line 286 "grammar.y"
{ yyval.i = Q_UDP; }
break;
case 66:
#line 287 "grammar.y"
{ yyval.i = Q_ICMP; }
break;
case 67:
#line 288 "grammar.y"
{ yyval.i = Q_IGMP; }
break;
case 68:
#line 289 "grammar.y"
{ yyval.i = Q_IGRP; }
break;
case 69:
#line 290 "grammar.y"
{ yyval.i = Q_PIM; }
break;
case 70:
#line 291 "grammar.y"
{ yyval.i = Q_VRRP; }
break;
case 71:
#line 292 "grammar.y"
{ yyval.i = Q_ATALK; }
break;
case 72:
#line 293 "grammar.y"
{ yyval.i = Q_AARP; }
break;
case 73:
#line 294 "grammar.y"
{ yyval.i = Q_DECNET; }
break;
case 74:
#line 295 "grammar.y"
{ yyval.i = Q_LAT; }
break;
case 75:
#line 296 "grammar.y"
{ yyval.i = Q_SCA; }
break;
case 76:
#line 297 "grammar.y"
{ yyval.i = Q_MOPDL; }
break;
case 77:
#line 298 "grammar.y"
{ yyval.i = Q_MOPRC; }
break;
case 78:
#line 299 "grammar.y"
{ yyval.i = Q_IPV6; }
break;
case 79:
#line 300 "grammar.y"
{ yyval.i = Q_ICMPV6; }
break;
case 80:
#line 301 "grammar.y"
{ yyval.i = Q_AH; }
break;
case 81:
#line 302 "grammar.y"
{ yyval.i = Q_ESP; }
break;
case 82:
#line 303 "grammar.y"
{ yyval.i = Q_ISO; }
break;
case 83:
#line 304 "grammar.y"
{ yyval.i = Q_ESIS; }
break;
case 84:
#line 305 "grammar.y"
{ yyval.i = Q_ISIS; }
break;
case 85:
#line 306 "grammar.y"
{ yyval.i = Q_ISIS_L1; }
break;
case 86:
#line 307 "grammar.y"
{ yyval.i = Q_ISIS_L2; }
break;
case 87:
#line 308 "grammar.y"
{ yyval.i = Q_ISIS_IIH; }
break;
case 88:
#line 309 "grammar.y"
{ yyval.i = Q_ISIS_LSP; }
break;
case 89:
#line 310 "grammar.y"
{ yyval.i = Q_ISIS_SNP; }
break;
case 90:
#line 311 "grammar.y"
{ yyval.i = Q_ISIS_PSNP; }
break;
case 91:
#line 312 "grammar.y"
{ yyval.i = Q_ISIS_CSNP; }
break;
case 92:
#line 313 "grammar.y"
{ yyval.i = Q_CLNP; }
break;
case 93:
#line 314 "grammar.y"
{ yyval.i = Q_STP; }
break;
case 94:
#line 315 "grammar.y"
{ yyval.i = Q_IPX; }
break;
case 95:
#line 316 "grammar.y"
{ yyval.i = Q_NETBEUI; }
break;
case 96:
#line 318 "grammar.y"
{ yyval.rblk = gen_broadcast(yyvsp[-1].i); }
break;
case 97:
#line 319 "grammar.y"
{ yyval.rblk = gen_multicast(yyvsp[-1].i); }
break;
case 98:
#line 320 "grammar.y"
{ yyval.rblk = gen_less(yyvsp[0].i); }
break;
case 99:
#line 321 "grammar.y"
{ yyval.rblk = gen_greater(yyvsp[0].i); }
break;
case 100:
#line 322 "grammar.y"
{ yyval.rblk = gen_byteop(yyvsp[-1].i, yyvsp[-2].i, yyvsp[0].i); }
break;
case 101:
#line 323 "grammar.y"
{ yyval.rblk = gen_inbound(0); }
break;
case 102:
#line 324 "grammar.y"
{ yyval.rblk = gen_inbound(1); }
break;
case 103:
#line 325 "grammar.y"
{ yyval.rblk = gen_vlan(yyvsp[0].i); }
break;
case 104:
#line 326 "grammar.y"
{ yyval.rblk = gen_vlan(-1); }
break;
case 105:
#line 327 "grammar.y"
{ yyval.rblk = yyvsp[0].rblk; }
break;
case 106:
#line 330 "grammar.y"
{ yyval.rblk = gen_pf_ifname(yyvsp[0].s); }
break;
case 107:
#line 331 "grammar.y"
{ yyval.rblk = gen_pf_ruleset(yyvsp[0].s); }
break;
case 108:
#line 332 "grammar.y"
{ yyval.rblk = gen_pf_rnr(yyvsp[0].i); }
break;
case 109:
#line 333 "grammar.y"
{ yyval.rblk = gen_pf_srnr(yyvsp[0].i); }
break;
case 110:
#line 334 "grammar.y"
{ yyval.rblk = gen_pf_reason(yyvsp[0].i); }
break;
case 111:
#line 335 "grammar.y"
{ yyval.rblk = gen_pf_action(yyvsp[0].i); }
break;
case 112:
#line 338 "grammar.y"
{ yyval.i = yyvsp[0].i; }
break;
case 113:
#line 339 "grammar.y"
{ const char *reasons[] = PFRES_NAMES;
				  int i;
				  for (i = 0; reasons[i]; i++) {
					  if (pcap_strcasecmp(yyvsp[0].s, reasons[i]) == 0) {
						  yyval.i = i;
						  break;
					  }
				  }
				  if (reasons[i] == NULL)
					  bpf_error("unknown PF reason");
				}
break;
case 114:
#line 352 "grammar.y"
{ if (pcap_strcasecmp(yyvsp[0].s, "pass") == 0 ||
				      pcap_strcasecmp(yyvsp[0].s, "accept") == 0)
					yyval.i = PF_PASS;
				  else if (pcap_strcasecmp(yyvsp[0].s, "drop") == 0 ||
				      pcap_strcasecmp(yyvsp[0].s, "block") == 0)
					yyval.i = PF_DROP;
				  else
					  bpf_error("unknown PF action");
				}
break;
case 115:
#line 363 "grammar.y"
{ yyval.i = BPF_JGT; }
break;
case 116:
#line 364 "grammar.y"
{ yyval.i = BPF_JGE; }
break;
case 117:
#line 365 "grammar.y"
{ yyval.i = BPF_JEQ; }
break;
case 118:
#line 367 "grammar.y"
{ yyval.i = BPF_JGT; }
break;
case 119:
#line 368 "grammar.y"
{ yyval.i = BPF_JGE; }
break;
case 120:
#line 369 "grammar.y"
{ yyval.i = BPF_JEQ; }
break;
case 121:
#line 371 "grammar.y"
{ yyval.a = gen_loadi(yyvsp[0].i); }
break;
case 123:
#line 374 "grammar.y"
{ yyval.a = gen_load(yyvsp[-3].i, yyvsp[-1].a, 1); }
break;
case 124:
#line 375 "grammar.y"
{ yyval.a = gen_load(yyvsp[-5].i, yyvsp[-3].a, yyvsp[-1].i); }
break;
case 125:
#line 376 "grammar.y"
{ yyval.a = gen_arth(BPF_ADD, yyvsp[-2].a, yyvsp[0].a); }
break;
case 126:
#line 377 "grammar.y"
{ yyval.a = gen_arth(BPF_SUB, yyvsp[-2].a, yyvsp[0].a); }
break;
case 127:
#line 378 "grammar.y"
{ yyval.a = gen_arth(BPF_MUL, yyvsp[-2].a, yyvsp[0].a); }
break;
case 128:
#line 379 "grammar.y"
{ yyval.a = gen_arth(BPF_DIV, yyvsp[-2].a, yyvsp[0].a); }
break;
case 129:
#line 380 "grammar.y"
{ yyval.a = gen_arth(BPF_AND, yyvsp[-2].a, yyvsp[0].a); }
break;
case 130:
#line 381 "grammar.y"
{ yyval.a = gen_arth(BPF_OR, yyvsp[-2].a, yyvsp[0].a); }
break;
case 131:
#line 382 "grammar.y"
{ yyval.a = gen_arth(BPF_LSH, yyvsp[-2].a, yyvsp[0].a); }
break;
case 132:
#line 383 "grammar.y"
{ yyval.a = gen_arth(BPF_RSH, yyvsp[-2].a, yyvsp[0].a); }
break;
case 133:
#line 384 "grammar.y"
{ yyval.a = gen_neg(yyvsp[0].a); }
break;
case 134:
#line 385 "grammar.y"
{ yyval.a = yyvsp[-1].a; }
break;
case 135:
#line 386 "grammar.y"
{ yyval.a = gen_loadlen(); }
break;
case 136:
#line 388 "grammar.y"
{ yyval.i = '&'; }
break;
case 137:
#line 389 "grammar.y"
{ yyval.i = '|'; }
break;
case 138:
#line 390 "grammar.y"
{ yyval.i = '<'; }
break;
case 139:
#line 391 "grammar.y"
{ yyval.i = '>'; }
break;
case 140:
#line 392 "grammar.y"
{ yyval.i = '='; }
break;
case 142:
#line 395 "grammar.y"
{ yyval.i = yyvsp[-1].i; }
break;
case 143:
#line 397 "grammar.y"
{ yyval.i = A_LANE; }
break;
case 144:
#line 398 "grammar.y"
{ yyval.i = A_LLC; }
break;
case 145:
#line 399 "grammar.y"
{ yyval.i = A_METAC;	}
break;
case 146:
#line 400 "grammar.y"
{ yyval.i = A_BCC; }
break;
case 147:
#line 401 "grammar.y"
{ yyval.i = A_OAMF4EC; }
break;
case 148:
#line 402 "grammar.y"
{ yyval.i = A_OAMF4SC; }
break;
case 149:
#line 403 "grammar.y"
{ yyval.i = A_SC; }
break;
case 150:
#line 404 "grammar.y"
{ yyval.i = A_ILMIC; }
break;
case 151:
#line 406 "grammar.y"
{ yyval.i = A_OAM; }
break;
case 152:
#line 407 "grammar.y"
{ yyval.i = A_OAMF4; }
break;
case 153:
#line 408 "grammar.y"
{ yyval.i = A_CONNECTMSG; }
break;
case 154:
#line 409 "grammar.y"
{ yyval.i = A_METACONNECT; }
break;
case 155:
#line 412 "grammar.y"
{ yyval.blk.atmfieldtype = A_VPI; }
break;
case 156:
#line 413 "grammar.y"
{ yyval.blk.atmfieldtype = A_VCI; }
break;
case 158:
#line 416 "grammar.y"
{ yyval.blk.b = gen_atmfield_code(yyvsp[-2].blk.atmfieldtype, (u_int)yyvsp[0].i, (u_int)yyvsp[-1].i, 0); }
break;
case 159:
#line 417 "grammar.y"
{ yyval.blk.b = gen_atmfield_code(yyvsp[-2].blk.atmfieldtype, (u_int)yyvsp[0].i, (u_int)yyvsp[-1].i, 1); }
break;
case 160:
#line 418 "grammar.y"
{ yyval.blk.b = yyvsp[-1].blk.b; yyval.blk.q = qerr; }
break;
case 161:
#line 420 "grammar.y"
{
	yyval.blk.atmfieldtype = yyvsp[-1].blk.atmfieldtype;
	if (yyval.blk.atmfieldtype == A_VPI ||
	    yyval.blk.atmfieldtype == A_VCI)
		yyval.blk.b = gen_atmfield_code(yyval.blk.atmfieldtype, (u_int) yyvsp[0].i, BPF_JEQ, 0);
	}
break;
case 163:
#line 428 "grammar.y"
{ gen_or(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
#line 1628 "y.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    return (1);
yyaccept:
    return (0);
}
