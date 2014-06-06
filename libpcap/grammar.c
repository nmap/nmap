/* A Bison parser, made by GNU Bison 3.0.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2013 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         pcap_parse
#define yylex           pcap_lex
#define yyerror         pcap_error
#define yydebug         pcap_debug
#define yynerrs         pcap_nerrs

#define yylval          pcap_lval
#define yychar          pcap_char

/* Copy the first part of user declarations.  */
#line 1 "grammar.y" /* yacc.c:339  */

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
    "@(#) $Header: /tcpdump/master/libpcap/grammar.y,v 1.101 2007-11-18 02:03:52 guy Exp $ (LBL)";
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
#include <arpa/inet.h>
#endif /* WIN32 */

#include <stdio.h>

#include "pcap-int.h"

#include "gencode.h"
#ifdef HAVE_NET_PFVAR_H
#include <net/if.h>
#include <net/pfvar.h>
#include <net/if_pflog.h>
#endif
#include "ieee80211.h"
#include <pcap/namedb.h>

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#define QSET(q, p, d, a) (q).proto = (p),\
			 (q).dir = (d),\
			 (q).addr = (a)

struct tok {
	int v;			/* value */
	const char *s;		/* string */
};

static const struct tok ieee80211_types[] = {
	{ IEEE80211_FC0_TYPE_DATA, "data" },
	{ IEEE80211_FC0_TYPE_MGT, "mgt" },
	{ IEEE80211_FC0_TYPE_MGT, "management" },
	{ IEEE80211_FC0_TYPE_CTL, "ctl" },
	{ IEEE80211_FC0_TYPE_CTL, "control" },
	{ 0, NULL }
};
static const struct tok ieee80211_mgt_subtypes[] = {
	{ IEEE80211_FC0_SUBTYPE_ASSOC_REQ, "assocreq" },
	{ IEEE80211_FC0_SUBTYPE_ASSOC_REQ, "assoc-req" },
	{ IEEE80211_FC0_SUBTYPE_ASSOC_RESP, "assocresp" },
	{ IEEE80211_FC0_SUBTYPE_ASSOC_RESP, "assoc-resp" },
	{ IEEE80211_FC0_SUBTYPE_REASSOC_REQ, "reassocreq" },
	{ IEEE80211_FC0_SUBTYPE_REASSOC_REQ, "reassoc-req" },
	{ IEEE80211_FC0_SUBTYPE_REASSOC_RESP, "reassocresp" },
	{ IEEE80211_FC0_SUBTYPE_REASSOC_RESP, "reassoc-resp" },
	{ IEEE80211_FC0_SUBTYPE_PROBE_REQ, "probereq" },
	{ IEEE80211_FC0_SUBTYPE_PROBE_REQ, "probe-req" },
	{ IEEE80211_FC0_SUBTYPE_PROBE_RESP, "proberesp" },
	{ IEEE80211_FC0_SUBTYPE_PROBE_RESP, "probe-resp" },
	{ IEEE80211_FC0_SUBTYPE_BEACON, "beacon" },
	{ IEEE80211_FC0_SUBTYPE_ATIM, "atim" },
	{ IEEE80211_FC0_SUBTYPE_DISASSOC, "disassoc" },
	{ IEEE80211_FC0_SUBTYPE_DISASSOC, "disassociation" },
	{ IEEE80211_FC0_SUBTYPE_AUTH, "auth" },
	{ IEEE80211_FC0_SUBTYPE_AUTH, "authentication" },
	{ IEEE80211_FC0_SUBTYPE_DEAUTH, "deauth" },
	{ IEEE80211_FC0_SUBTYPE_DEAUTH, "deauthentication" },
	{ 0, NULL }
};
static const struct tok ieee80211_ctl_subtypes[] = {
	{ IEEE80211_FC0_SUBTYPE_PS_POLL, "ps-poll" },
	{ IEEE80211_FC0_SUBTYPE_RTS, "rts" },
	{ IEEE80211_FC0_SUBTYPE_CTS, "cts" },
	{ IEEE80211_FC0_SUBTYPE_ACK, "ack" },
	{ IEEE80211_FC0_SUBTYPE_CF_END, "cf-end" },
	{ IEEE80211_FC0_SUBTYPE_CF_END_ACK, "cf-end-ack" },
	{ 0, NULL }
};
static const struct tok ieee80211_data_subtypes[] = {
	{ IEEE80211_FC0_SUBTYPE_DATA, "data" },
	{ IEEE80211_FC0_SUBTYPE_CF_ACK, "data-cf-ack" },
	{ IEEE80211_FC0_SUBTYPE_CF_POLL, "data-cf-poll" },
	{ IEEE80211_FC0_SUBTYPE_CF_ACPL, "data-cf-ack-poll" },
	{ IEEE80211_FC0_SUBTYPE_NODATA, "null" },
	{ IEEE80211_FC0_SUBTYPE_NODATA_CF_ACK, "cf-ack" },
	{ IEEE80211_FC0_SUBTYPE_NODATA_CF_POLL, "cf-poll"  },
	{ IEEE80211_FC0_SUBTYPE_NODATA_CF_ACPL, "cf-ack-poll" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_DATA, "qos-data" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_CF_ACK, "qos-data-cf-ack" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_CF_POLL, "qos-data-cf-poll" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_CF_ACPL, "qos-data-cf-ack-poll" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_NODATA, "qos" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_NODATA_CF_POLL, "qos-cf-poll" },
	{ IEEE80211_FC0_SUBTYPE_QOS|IEEE80211_FC0_SUBTYPE_NODATA_CF_ACPL, "qos-cf-ack-poll" },
	{ 0, NULL }
};
struct type2tok {
	int type;
	const struct tok *tok;
};
static const struct type2tok ieee80211_type_subtypes[] = {
	{ IEEE80211_FC0_TYPE_MGT, ieee80211_mgt_subtypes },
	{ IEEE80211_FC0_TYPE_CTL, ieee80211_ctl_subtypes },
	{ IEEE80211_FC0_TYPE_DATA, ieee80211_data_subtypes },
	{ 0, NULL }
};

static int
str2tok(const char *str, const struct tok *toks)
{
	int i;

	for (i = 0; toks[i].s != NULL; i++) {
		if (pcap_strcasecmp(toks[i].s, str) == 0)
			return (toks[i].v);
	}
	return (-1);
}

int n_errors = 0;

static struct qual qerr = { Q_UNDEF, Q_UNDEF, Q_UNDEF, Q_UNDEF };

static void
yyerror(const char *msg)
{
	++n_errors;
	bpf_error("%s", msg);
	/* NOTREACHED */
}

#ifdef NEED_YYPARSE_WRAPPER
int yyparse(void);

int
pcap_parse()
{
	return (yyparse());
}
#endif

#ifdef HAVE_NET_PFVAR_H
static int
pfreason_to_num(const char *reason)
{
	const char *reasons[] = PFRES_NAMES;
	int i;

	for (i = 0; reasons[i]; i++) {
		if (pcap_strcasecmp(reason, reasons[i]) == 0)
			return (i);
	}
	bpf_error("unknown PF reason");
	/*NOTREACHED*/
}

static int
pfaction_to_num(const char *action)
{
	if (pcap_strcasecmp(action, "pass") == 0 ||
	    pcap_strcasecmp(action, "accept") == 0)
		return (PF_PASS);
	else if (pcap_strcasecmp(action, "drop") == 0 ||
		pcap_strcasecmp(action, "block") == 0)
		return (PF_DROP);
#if HAVE_PF_NAT_THROUGH_PF_NORDR
	else if (pcap_strcasecmp(action, "rdr") == 0)
		return (PF_RDR);
	else if (pcap_strcasecmp(action, "nat") == 0)
		return (PF_NAT);
	else if (pcap_strcasecmp(action, "binat") == 0)
		return (PF_BINAT);
	else if (pcap_strcasecmp(action, "nordr") == 0)
		return (PF_NORDR);
#endif
	else {
		bpf_error("unknown PF action");
		/*NOTREACHED*/
	}
}
#else /* !HAVE_NET_PFVAR_H */
static int
pfreason_to_num(const char *reason)
{
	bpf_error("libpcap was compiled on a machine without pf support");
	/*NOTREACHED*/

	/* this is to make the VC compiler happy */
	return -1;
}

static int
pfaction_to_num(const char *action)
{
	bpf_error("libpcap was compiled on a machine without pf support");
	/*NOTREACHED*/

	/* this is to make the VC compiler happy */
	return -1;
}
#endif /* HAVE_NET_PFVAR_H */

#line 315 "y.tab.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
#ifndef YY_PCAP_Y_TAB_H_INCLUDED
# define YY_PCAP_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int pcap_debug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    DST = 258,
    SRC = 259,
    HOST = 260,
    GATEWAY = 261,
    NET = 262,
    NETMASK = 263,
    PORT = 264,
    PORTRANGE = 265,
    LESS = 266,
    GREATER = 267,
    PROTO = 268,
    PROTOCHAIN = 269,
    CBYTE = 270,
    ARP = 271,
    RARP = 272,
    IP = 273,
    SCTP = 274,
    TCP = 275,
    UDP = 276,
    ICMP = 277,
    IGMP = 278,
    IGRP = 279,
    PIM = 280,
    VRRP = 281,
    CARP = 282,
    ATALK = 283,
    AARP = 284,
    DECNET = 285,
    LAT = 286,
    SCA = 287,
    MOPRC = 288,
    MOPDL = 289,
    TK_BROADCAST = 290,
    TK_MULTICAST = 291,
    NUM = 292,
    INBOUND = 293,
    OUTBOUND = 294,
    PF_IFNAME = 295,
    PF_RSET = 296,
    PF_RNR = 297,
    PF_SRNR = 298,
    PF_REASON = 299,
    PF_ACTION = 300,
    TYPE = 301,
    SUBTYPE = 302,
    DIR = 303,
    ADDR1 = 304,
    ADDR2 = 305,
    ADDR3 = 306,
    ADDR4 = 307,
    RA = 308,
    TA = 309,
    LINK = 310,
    GEQ = 311,
    LEQ = 312,
    NEQ = 313,
    ID = 314,
    EID = 315,
    HID = 316,
    HID6 = 317,
    AID = 318,
    LSH = 319,
    RSH = 320,
    LEN = 321,
    IPV6 = 322,
    ICMPV6 = 323,
    AH = 324,
    ESP = 325,
    VLAN = 326,
    MPLS = 327,
    PPPOED = 328,
    PPPOES = 329,
    ISO = 330,
    ESIS = 331,
    CLNP = 332,
    ISIS = 333,
    L1 = 334,
    L2 = 335,
    IIH = 336,
    LSP = 337,
    SNP = 338,
    CSNP = 339,
    PSNP = 340,
    STP = 341,
    IPX = 342,
    NETBEUI = 343,
    LANE = 344,
    LLC = 345,
    METAC = 346,
    BCC = 347,
    SC = 348,
    ILMIC = 349,
    OAMF4EC = 350,
    OAMF4SC = 351,
    OAM = 352,
    OAMF4 = 353,
    CONNECTMSG = 354,
    METACONNECT = 355,
    VPI = 356,
    VCI = 357,
    RADIO = 358,
    FISU = 359,
    LSSU = 360,
    MSU = 361,
    HFISU = 362,
    HLSSU = 363,
    HMSU = 364,
    SIO = 365,
    OPC = 366,
    DPC = 367,
    SLS = 368,
    HSIO = 369,
    HOPC = 370,
    HDPC = 371,
    HSLS = 372,
    OR = 373,
    AND = 374,
    UMINUS = 375
  };
#endif
/* Tokens.  */
#define DST 258
#define SRC 259
#define HOST 260
#define GATEWAY 261
#define NET 262
#define NETMASK 263
#define PORT 264
#define PORTRANGE 265
#define LESS 266
#define GREATER 267
#define PROTO 268
#define PROTOCHAIN 269
#define CBYTE 270
#define ARP 271
#define RARP 272
#define IP 273
#define SCTP 274
#define TCP 275
#define UDP 276
#define ICMP 277
#define IGMP 278
#define IGRP 279
#define PIM 280
#define VRRP 281
#define CARP 282
#define ATALK 283
#define AARP 284
#define DECNET 285
#define LAT 286
#define SCA 287
#define MOPRC 288
#define MOPDL 289
#define TK_BROADCAST 290
#define TK_MULTICAST 291
#define NUM 292
#define INBOUND 293
#define OUTBOUND 294
#define PF_IFNAME 295
#define PF_RSET 296
#define PF_RNR 297
#define PF_SRNR 298
#define PF_REASON 299
#define PF_ACTION 300
#define TYPE 301
#define SUBTYPE 302
#define DIR 303
#define ADDR1 304
#define ADDR2 305
#define ADDR3 306
#define ADDR4 307
#define RA 308
#define TA 309
#define LINK 310
#define GEQ 311
#define LEQ 312
#define NEQ 313
#define ID 314
#define EID 315
#define HID 316
#define HID6 317
#define AID 318
#define LSH 319
#define RSH 320
#define LEN 321
#define IPV6 322
#define ICMPV6 323
#define AH 324
#define ESP 325
#define VLAN 326
#define MPLS 327
#define PPPOED 328
#define PPPOES 329
#define ISO 330
#define ESIS 331
#define CLNP 332
#define ISIS 333
#define L1 334
#define L2 335
#define IIH 336
#define LSP 337
#define SNP 338
#define CSNP 339
#define PSNP 340
#define STP 341
#define IPX 342
#define NETBEUI 343
#define LANE 344
#define LLC 345
#define METAC 346
#define BCC 347
#define SC 348
#define ILMIC 349
#define OAMF4EC 350
#define OAMF4SC 351
#define OAM 352
#define OAMF4 353
#define CONNECTMSG 354
#define METACONNECT 355
#define VPI 356
#define VCI 357
#define RADIO 358
#define FISU 359
#define LSSU 360
#define MSU 361
#define HFISU 362
#define HLSSU 363
#define HMSU 364
#define SIO 365
#define OPC 366
#define DPC 367
#define SLS 368
#define HSIO 369
#define HOPC 370
#define HDPC 371
#define HSLS 372
#define OR 373
#define AND 374
#define UMINUS 375

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE YYSTYPE;
union YYSTYPE
{
#line 242 "grammar.y" /* yacc.c:355  */

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

#line 611 "y.tab.c" /* yacc.c:355  */
};
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE pcap_lval;

int pcap_parse (void);

#endif /* !YY_PCAP_Y_TAB_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 626 "y.tab.c" /* yacc.c:358  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   710

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  136
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  46
/* YYNRULES -- Number of rules.  */
#define YYNRULES  213
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  285

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   375

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   120,     2,     2,     2,     2,   122,     2,
     129,   128,   125,   123,     2,   124,     2,   126,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,   135,     2,
     132,   131,   130,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   133,     2,   134,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,   121,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   127
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   316,   316,   320,   322,   324,   325,   326,   327,   328,
     330,   332,   334,   335,   337,   339,   340,   342,   344,   357,
     366,   375,   384,   393,   395,   397,   399,   400,   401,   403,
     405,   407,   408,   410,   411,   412,   413,   414,   415,   417,
     418,   419,   420,   422,   424,   425,   426,   427,   428,   429,
     432,   433,   436,   437,   438,   439,   440,   441,   442,   443,
     444,   445,   446,   447,   450,   451,   452,   453,   456,   458,
     459,   460,   461,   462,   463,   464,   465,   466,   467,   468,
     469,   470,   471,   472,   473,   474,   475,   476,   477,   478,
     479,   480,   481,   482,   483,   484,   485,   486,   487,   488,
     489,   490,   491,   492,   493,   494,   495,   496,   498,   499,
     500,   501,   502,   503,   504,   505,   506,   507,   508,   509,
     510,   511,   512,   513,   516,   517,   518,   519,   520,   521,
     524,   529,   532,   536,   539,   540,   546,   547,   567,   583,
     584,   597,   598,   601,   604,   605,   606,   608,   609,   610,
     612,   613,   615,   616,   617,   618,   619,   620,   621,   622,
     623,   624,   625,   626,   627,   629,   630,   631,   632,   633,
     635,   636,   638,   639,   640,   641,   642,   643,   644,   645,
     647,   648,   649,   650,   653,   654,   656,   657,   658,   659,
     661,   668,   669,   672,   673,   674,   675,   676,   677,   680,
     681,   682,   683,   684,   685,   686,   687,   689,   690,   691,
     692,   694,   707,   708
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "DST", "SRC", "HOST", "GATEWAY", "NET",
  "NETMASK", "PORT", "PORTRANGE", "LESS", "GREATER", "PROTO", "PROTOCHAIN",
  "CBYTE", "ARP", "RARP", "IP", "SCTP", "TCP", "UDP", "ICMP", "IGMP",
  "IGRP", "PIM", "VRRP", "CARP", "ATALK", "AARP", "DECNET", "LAT", "SCA",
  "MOPRC", "MOPDL", "TK_BROADCAST", "TK_MULTICAST", "NUM", "INBOUND",
  "OUTBOUND", "PF_IFNAME", "PF_RSET", "PF_RNR", "PF_SRNR", "PF_REASON",
  "PF_ACTION", "TYPE", "SUBTYPE", "DIR", "ADDR1", "ADDR2", "ADDR3",
  "ADDR4", "RA", "TA", "LINK", "GEQ", "LEQ", "NEQ", "ID", "EID", "HID",
  "HID6", "AID", "LSH", "RSH", "LEN", "IPV6", "ICMPV6", "AH", "ESP",
  "VLAN", "MPLS", "PPPOED", "PPPOES", "ISO", "ESIS", "CLNP", "ISIS", "L1",
  "L2", "IIH", "LSP", "SNP", "CSNP", "PSNP", "STP", "IPX", "NETBEUI",
  "LANE", "LLC", "METAC", "BCC", "SC", "ILMIC", "OAMF4EC", "OAMF4SC",
  "OAM", "OAMF4", "CONNECTMSG", "METACONNECT", "VPI", "VCI", "RADIO",
  "FISU", "LSSU", "MSU", "HFISU", "HLSSU", "HMSU", "SIO", "OPC", "DPC",
  "SLS", "HSIO", "HOPC", "HDPC", "HSLS", "OR", "AND", "'!'", "'|'", "'&'",
  "'+'", "'-'", "'*'", "'/'", "UMINUS", "')'", "'('", "'>'", "'='", "'<'",
  "'['", "']'", "':'", "$accept", "prog", "null", "expr", "and", "or",
  "id", "nid", "not", "paren", "pid", "qid", "term", "head", "rterm",
  "pqual", "dqual", "aqual", "ndaqual", "pname", "other", "pfvar",
  "p80211", "type", "subtype", "type_subtype", "dir", "reason", "action",
  "relop", "irelop", "arth", "narth", "byteop", "pnum", "atmtype",
  "atmmultitype", "atmfield", "atmvalue", "atmfieldvalue", "atmlistvalue",
  "mtp2type", "mtp3field", "mtp3value", "mtp3fieldvalue", "mtp3listvalue", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
      33,   124,    38,    43,    45,    42,    47,   375,    41,    40,
      62,    61,    60,    91,    93,    58
};
# endif

#define YYPACT_NINF -208

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-208)))

#define YYTABLE_NINF -42

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
    -208,    15,   226,  -208,     1,    30,    32,  -208,  -208,  -208,
    -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,
    -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,   -31,
     -15,    49,    68,   -18,    62,  -208,  -208,  -208,  -208,  -208,
    -208,   -26,   -26,  -208,   -26,  -208,  -208,  -208,  -208,  -208,
    -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,
    -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,
    -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,
    -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,   570,
    -208,   -42,   456,   456,  -208,    19,  -208,   656,    12,  -208,
    -208,   153,  -208,  -208,  -208,  -208,    55,  -208,    59,  -208,
    -208,   -69,  -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,
    -208,   -26,  -208,  -208,  -208,   570,   -19,  -208,  -208,  -208,
     341,   341,  -208,   -93,   -10,    -1,  -208,  -208,    -6,    21,
    -208,  -208,  -208,    19,    19,  -208,    -9,     6,  -208,  -208,
    -208,  -208,  -208,  -208,  -208,  -208,  -208,   -14,    74,   -13,
    -208,  -208,  -208,  -208,  -208,  -208,   171,  -208,  -208,  -208,
     570,  -208,  -208,  -208,   570,   570,   570,   570,   570,   570,
     570,   570,  -208,  -208,  -208,   570,   570,  -208,   112,   123,
     128,  -208,  -208,  -208,   129,   130,   131,  -208,  -208,  -208,
    -208,  -208,  -208,  -208,   134,    -1,    79,  -208,   341,   341,
    -208,     4,  -208,  -208,  -208,  -208,  -208,   116,   142,   145,
    -208,  -208,    64,   -42,    -1,   179,   189,   191,   192,  -208,
    -208,   149,  -208,  -208,  -208,  -208,  -208,  -208,   -51,   -92,
     -92,    99,   110,    33,    33,  -208,  -208,    79,    79,  -208,
    -101,  -208,  -208,  -208,   -98,  -208,  -208,  -208,   -64,  -208,
    -208,  -208,  -208,    19,    19,  -208,  -208,  -208,  -208,    -8,
    -208,   160,  -208,   112,  -208,   129,  -208,  -208,  -208,  -208,
    -208,    65,  -208,  -208,  -208
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       4,     0,    51,     1,     0,     0,     0,    71,    72,    70,
      73,    74,    75,    76,    77,    78,    79,    80,    81,    82,
      83,    84,    85,    86,    88,    87,   170,   113,   114,     0,
       0,     0,     0,     0,     0,    69,   164,    89,    90,    91,
      92,   116,   118,   119,   121,    93,    94,   103,    95,    96,
      97,    98,    99,   100,   102,   101,   104,   105,   106,   172,
     173,   174,   175,   178,   179,   176,   177,   180,   181,   182,
     183,   184,   185,   107,   193,   194,   195,   196,   197,   198,
     199,   200,   201,   202,   203,   204,   205,   206,    24,     0,
      25,     2,    51,    51,     5,     0,    31,     0,    50,    44,
     122,     0,   151,   150,    45,    46,     0,    48,     0,   110,
     111,     0,   124,   125,   126,   127,   141,   142,   128,   143,
     129,     0,   115,   117,   120,     0,     0,   162,    11,    10,
      51,    51,    32,     0,   151,   150,    15,    21,    18,    20,
      22,    39,    12,     0,     0,    13,    53,    52,    64,    68,
      65,    66,    67,    36,    37,   108,   109,     0,     0,     0,
      58,    59,    60,    61,    62,    63,    34,    35,    38,   123,
       0,   145,   147,   149,     0,     0,     0,     0,     0,     0,
       0,     0,   144,   146,   148,     0,     0,   190,     0,     0,
       0,    47,   186,   211,     0,     0,     0,    49,   207,   166,
     165,   168,   169,   167,     0,     0,     0,     7,    51,    51,
       6,   150,     9,     8,    40,   163,   171,     0,     0,     0,
      23,    26,    30,     0,    29,     0,     0,     0,     0,   134,
     135,   131,   138,   132,   139,   140,   133,    33,     0,   160,
     161,   159,   158,   154,   155,   156,   157,    42,    43,   191,
       0,   187,   188,   212,     0,   208,   209,   112,   150,    17,
      16,    19,    14,     0,     0,    55,    57,    54,    56,     0,
     152,     0,   189,     0,   210,     0,    27,    28,   136,   137,
     130,     0,   192,   213,   153
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -208,  -208,  -208,   196,   -11,  -207,   -94,  -122,     5,    -2,
    -208,  -208,   -82,  -208,  -208,  -208,  -208,    42,  -208,     7,
    -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,  -208,   -48,
     -40,   -24,   -75,  -208,   -36,  -208,  -208,  -208,  -208,  -185,
    -208,  -208,  -208,  -208,  -173,  -208
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     2,   133,   130,   131,   220,   142,   143,   125,
     222,   223,    94,    95,    96,    97,   166,   167,   168,   126,
      99,   100,   169,   231,   280,   233,   236,   118,   120,   185,
     186,   101,   102,   204,   103,   104,   105,   106,   191,   192,
     250,   107,   108,   197,   198,   254
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      93,   141,   217,   249,   -13,   122,   123,    92,   124,    98,
     132,    26,   -41,   174,   175,     3,   264,   128,   134,   116,
     128,   253,   221,   229,   234,   128,   129,   272,   112,   278,
     274,   178,   179,   180,   181,   214,   207,   212,   109,   121,
     121,   117,   121,   273,   113,   230,   235,   275,   210,   213,
     134,   279,   199,   200,   -29,   -29,    26,   135,   189,   145,
     195,   201,   202,   203,   216,   127,   190,   110,   196,   111,
     176,   177,   178,   179,   180,   181,   128,   129,   136,   137,
     138,   139,   140,   270,   271,   205,   114,   221,   282,   135,
      93,    93,   187,   144,   211,   211,   193,    92,    92,    98,
      98,   206,   283,    90,   188,   115,   194,   145,   224,   225,
     226,   171,   172,   173,   170,   171,   172,   173,   215,   121,
     218,   119,   -13,   -13,   227,   228,   132,   216,   209,   209,
     -41,   -41,   -13,   232,   134,   208,   208,    98,    98,    88,
     -41,   144,   121,   174,   175,   170,   238,   219,    90,   187,
     239,   240,   241,   242,   243,   244,   245,   246,   180,   181,
     251,   247,   248,   174,   175,   252,   193,   255,   256,   276,
     277,   257,   211,   258,   174,   175,   148,   259,   150,   260,
     151,   152,   261,   265,    90,   182,   183,   184,    90,   182,
     183,   184,   262,   266,   267,   268,   269,   281,    91,   284,
     176,   177,   178,   179,   180,   181,   209,    93,   237,   171,
     172,   173,   263,   208,   208,    98,    98,   174,   175,     0,
       0,   177,   178,   179,   180,   181,    -3,   145,   145,     0,
       0,     0,     0,   178,   179,   180,   181,     4,     5,     0,
       0,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,   144,   144,    26,    27,    28,    29,    30,    31,    32,
      33,    34,     0,     0,   176,   177,   178,   179,   180,   181,
       0,    35,     0,   182,   183,   184,     0,     0,     0,     0,
       0,     0,    36,    37,    38,    39,    40,    41,    42,    43,
      44,    45,    46,    47,    48,    49,    50,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    60,    61,    62,    63,
      64,    65,    66,    67,    68,    69,    70,    71,    72,    73,
      74,    75,    76,    77,    78,    79,    80,    81,    82,    83,
      84,    85,    86,    87,     0,     0,    88,     0,     0,     0,
      89,     0,     4,     5,     0,    90,     6,     7,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,     0,     0,    26,    27,
      28,    29,    30,    31,    32,    33,    34,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    35,     0,     0,     0,
     136,   137,   138,   139,   140,     0,     0,    36,    37,    38,
      39,    40,    41,    42,    43,    44,    45,    46,    47,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,    68,
      69,    70,    71,    72,    73,    74,    75,    76,    77,    78,
      79,    80,    81,    82,    83,    84,    85,    86,    87,     0,
       0,    88,     0,     0,     0,    89,     0,     4,     5,     0,
      90,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,     0,     0,    26,    27,    28,    29,    30,    31,    32,
      33,    34,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    35,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    36,    37,    38,    39,    40,    41,    42,    43,
      44,    45,    46,    47,    48,    49,    50,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    60,    61,    62,    63,
      64,    65,    66,    67,    68,    69,    70,    71,    72,    73,
      74,    75,    76,    77,    78,    79,    80,    81,    82,    83,
      84,    85,    86,    87,     0,     0,    88,     0,     0,     0,
      89,     0,     0,     0,     0,    90,     7,     8,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,     0,     0,    26,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    35,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    36,    37,    38,    39,
      40,     0,     0,     0,     0,    45,    46,    47,    48,    49,
      50,    51,    52,    53,    54,    55,    56,    57,    58,   146,
     147,   148,   149,   150,     0,   151,   152,     0,     0,   153,
     154,     0,     0,    73,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   155,   156,     0,    89,     0,     0,     0,     0,    90,
       0,     0,   157,   158,   159,   160,   161,   162,   163,   164,
     165
};

static const yytype_int16 yycheck[] =
{
       2,    95,     8,   188,     0,    41,    42,     2,    44,     2,
      92,    37,     0,    64,    65,     0,   223,   118,    93,    37,
     118,   194,   144,    37,    37,   118,   119,   128,    59,    37,
     128,   123,   124,   125,   126,   128,   130,   131,    37,    41,
      42,    59,    44,   250,    59,    59,    59,   254,   130,   131,
     125,    59,   121,   122,   118,   119,    37,    93,   106,    95,
     108,   130,   131,   132,   128,    89,   106,    37,   108,    37,
     121,   122,   123,   124,   125,   126,   118,   119,    59,    60,
      61,    62,    63,   134,   135,   121,    37,   209,   273,   125,
      92,    93,    37,    95,   130,   131,    37,    92,    93,    92,
      93,   125,   275,   129,   106,    37,   108,   143,   144,   118,
     119,    56,    57,    58,   133,    56,    57,    58,   128,   121,
     126,    59,   118,   119,   118,   119,   208,   128,   130,   131,
     118,   119,   128,    59,   209,   130,   131,   130,   131,   120,
     128,   143,   144,    64,    65,   133,   170,   126,   129,    37,
     174,   175,   176,   177,   178,   179,   180,   181,   125,   126,
      37,   185,   186,    64,    65,    37,    37,    37,    37,   263,
     264,    37,   208,   209,    64,    65,     5,    61,     7,    37,
       9,    10,    37,     4,   129,   130,   131,   132,   129,   130,
     131,   132,   128,     4,     3,     3,    47,    37,     2,   134,
     121,   122,   123,   124,   125,   126,   208,   209,   166,    56,
      57,    58,   223,   208,   209,   208,   209,    64,    65,    -1,
      -1,   122,   123,   124,   125,   126,     0,   263,   264,    -1,
      -1,    -1,    -1,   123,   124,   125,   126,    11,    12,    -1,
      -1,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,   263,   264,    37,    38,    39,    40,    41,    42,    43,
      44,    45,    -1,    -1,   121,   122,   123,   124,   125,   126,
      -1,    55,    -1,   130,   131,   132,    -1,    -1,    -1,    -1,
      -1,    -1,    66,    67,    68,    69,    70,    71,    72,    73,
      74,    75,    76,    77,    78,    79,    80,    81,    82,    83,
      84,    85,    86,    87,    88,    89,    90,    91,    92,    93,
      94,    95,    96,    97,    98,    99,   100,   101,   102,   103,
     104,   105,   106,   107,   108,   109,   110,   111,   112,   113,
     114,   115,   116,   117,    -1,    -1,   120,    -1,    -1,    -1,
     124,    -1,    11,    12,    -1,   129,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    -1,    -1,    37,    38,
      39,    40,    41,    42,    43,    44,    45,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    55,    -1,    -1,    -1,
      59,    60,    61,    62,    63,    -1,    -1,    66,    67,    68,
      69,    70,    71,    72,    73,    74,    75,    76,    77,    78,
      79,    80,    81,    82,    83,    84,    85,    86,    87,    88,
      89,    90,    91,    92,    93,    94,    95,    96,    97,    98,
      99,   100,   101,   102,   103,   104,   105,   106,   107,   108,
     109,   110,   111,   112,   113,   114,   115,   116,   117,    -1,
      -1,   120,    -1,    -1,    -1,   124,    -1,    11,    12,    -1,
     129,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    -1,    -1,    37,    38,    39,    40,    41,    42,    43,
      44,    45,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    55,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    66,    67,    68,    69,    70,    71,    72,    73,
      74,    75,    76,    77,    78,    79,    80,    81,    82,    83,
      84,    85,    86,    87,    88,    89,    90,    91,    92,    93,
      94,    95,    96,    97,    98,    99,   100,   101,   102,   103,
     104,   105,   106,   107,   108,   109,   110,   111,   112,   113,
     114,   115,   116,   117,    -1,    -1,   120,    -1,    -1,    -1,
     124,    -1,    -1,    -1,    -1,   129,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    -1,    -1,    37,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    55,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    66,    67,    68,    69,
      70,    -1,    -1,    -1,    -1,    75,    76,    77,    78,    79,
      80,    81,    82,    83,    84,    85,    86,    87,    88,     3,
       4,     5,     6,     7,    -1,     9,    10,    -1,    -1,    13,
      14,    -1,    -1,   103,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    35,    36,    -1,   124,    -1,    -1,    -1,    -1,   129,
      -1,    -1,    46,    47,    48,    49,    50,    51,    52,    53,
      54
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,   137,   138,     0,    11,    12,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    37,    38,    39,    40,
      41,    42,    43,    44,    45,    55,    66,    67,    68,    69,
      70,    71,    72,    73,    74,    75,    76,    77,    78,    79,
      80,    81,    82,    83,    84,    85,    86,    87,    88,    89,
      90,    91,    92,    93,    94,    95,    96,    97,    98,    99,
     100,   101,   102,   103,   104,   105,   106,   107,   108,   109,
     110,   111,   112,   113,   114,   115,   116,   117,   120,   124,
     129,   139,   144,   145,   148,   149,   150,   151,   155,   156,
     157,   167,   168,   170,   171,   172,   173,   177,   178,    37,
      37,    37,    59,    59,    37,    37,    37,    59,   163,    59,
     164,   145,   170,   170,   170,   145,   155,   167,   118,   119,
     140,   141,   148,   139,   168,   170,    59,    60,    61,    62,
      63,   142,   143,   144,   145,   170,     3,     4,     5,     6,
       7,     9,    10,    13,    14,    35,    36,    46,    47,    48,
      49,    50,    51,    52,    53,    54,   152,   153,   154,   158,
     133,    56,    57,    58,    64,    65,   121,   122,   123,   124,
     125,   126,   130,   131,   132,   165,   166,    37,   145,   165,
     166,   174,   175,    37,   145,   165,   166,   179,   180,   121,
     122,   130,   131,   132,   169,   170,   167,   142,   144,   145,
     148,   170,   142,   148,   128,   128,   128,     8,   126,   126,
     142,   143,   146,   147,   170,   118,   119,   118,   119,    37,
      59,   159,    59,   161,    37,    59,   162,   153,   167,   167,
     167,   167,   167,   167,   167,   167,   167,   167,   167,   175,
     176,    37,    37,   180,   181,    37,    37,    37,   170,    61,
      37,    37,   128,   140,   141,     4,     4,     3,     3,    47,
     134,   135,   128,   141,   128,   141,   142,   142,    37,    59,
     160,    37,   175,   180,   134
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,   136,   137,   137,   138,   139,   139,   139,   139,   139,
     140,   141,   142,   142,   142,   143,   143,   143,   143,   143,
     143,   143,   143,   143,   144,   145,   146,   146,   146,   147,
     147,   148,   148,   149,   149,   149,   149,   149,   149,   150,
     150,   150,   150,   150,   150,   150,   150,   150,   150,   150,
     151,   151,   152,   152,   152,   152,   152,   152,   152,   152,
     152,   152,   152,   152,   153,   153,   153,   153,   154,   155,
     155,   155,   155,   155,   155,   155,   155,   155,   155,   155,
     155,   155,   155,   155,   155,   155,   155,   155,   155,   155,
     155,   155,   155,   155,   155,   155,   155,   155,   155,   155,
     155,   155,   155,   155,   155,   155,   155,   155,   156,   156,
     156,   156,   156,   156,   156,   156,   156,   156,   156,   156,
     156,   156,   156,   156,   157,   157,   157,   157,   157,   157,
     158,   158,   158,   158,   159,   159,   160,   160,   161,   162,
     162,   163,   163,   164,   165,   165,   165,   166,   166,   166,
     167,   167,   168,   168,   168,   168,   168,   168,   168,   168,
     168,   168,   168,   168,   168,   169,   169,   169,   169,   169,
     170,   170,   171,   171,   171,   171,   171,   171,   171,   171,
     172,   172,   172,   172,   173,   173,   174,   174,   174,   174,
     175,   176,   176,   177,   177,   177,   177,   177,   177,   178,
     178,   178,   178,   178,   178,   178,   178,   179,   179,   179,
     179,   180,   181,   181
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     2,     1,     0,     1,     3,     3,     3,     3,
       1,     1,     1,     1,     3,     1,     3,     3,     1,     3,
       1,     1,     1,     2,     1,     1,     1,     3,     3,     1,
       1,     1,     2,     3,     2,     2,     2,     2,     2,     2,
       3,     1,     3,     3,     1,     1,     1,     2,     1,     2,
       1,     0,     1,     1,     3,     3,     3,     3,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     2,     2,
       2,     2,     4,     1,     1,     2,     1,     2,     1,     1,
       2,     1,     1,     2,     2,     2,     2,     2,     2,     2,
       4,     2,     2,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     4,     6,     3,     3,     3,     3,     3,     3,
       3,     3,     2,     3,     1,     1,     1,     1,     1,     1,
       1,     3,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     2,     2,     3,
       1,     1,     3,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     2,     2,
       3,     1,     1,     3
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                                              );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
{
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);

        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 317 "grammar.y" /* yacc.c:1646  */
    {
	finish_parse((yyvsp[0].blk).b);
}
#line 2036 "y.tab.c" /* yacc.c:1646  */
    break;

  case 4:
#line 322 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).q = qerr; }
#line 2042 "y.tab.c" /* yacc.c:1646  */
    break;

  case 6:
#line 325 "grammar.y" /* yacc.c:1646  */
    { gen_and((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2048 "y.tab.c" /* yacc.c:1646  */
    break;

  case 7:
#line 326 "grammar.y" /* yacc.c:1646  */
    { gen_and((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2054 "y.tab.c" /* yacc.c:1646  */
    break;

  case 8:
#line 327 "grammar.y" /* yacc.c:1646  */
    { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2060 "y.tab.c" /* yacc.c:1646  */
    break;

  case 9:
#line 328 "grammar.y" /* yacc.c:1646  */
    { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2066 "y.tab.c" /* yacc.c:1646  */
    break;

  case 10:
#line 330 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk) = (yyvsp[-1].blk); }
#line 2072 "y.tab.c" /* yacc.c:1646  */
    break;

  case 11:
#line 332 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk) = (yyvsp[-1].blk); }
#line 2078 "y.tab.c" /* yacc.c:1646  */
    break;

  case 13:
#line 335 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_ncode(NULL, (bpf_u_int32)(yyvsp[0].i),
						   (yyval.blk).q = (yyvsp[-1].blk).q); }
#line 2085 "y.tab.c" /* yacc.c:1646  */
    break;

  case 14:
#line 337 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk) = (yyvsp[-1].blk); }
#line 2091 "y.tab.c" /* yacc.c:1646  */
    break;

  case 15:
#line 339 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_scode((yyvsp[0].s), (yyval.blk).q = (yyvsp[-1].blk).q); }
#line 2097 "y.tab.c" /* yacc.c:1646  */
    break;

  case 16:
#line 340 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_mcode((yyvsp[-2].s), NULL, (yyvsp[0].i),
				    (yyval.blk).q = (yyvsp[-3].blk).q); }
#line 2104 "y.tab.c" /* yacc.c:1646  */
    break;

  case 17:
#line 342 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_mcode((yyvsp[-2].s), (yyvsp[0].s), 0,
				    (yyval.blk).q = (yyvsp[-3].blk).q); }
#line 2111 "y.tab.c" /* yacc.c:1646  */
    break;

  case 18:
#line 344 "grammar.y" /* yacc.c:1646  */
    {
				  /* Decide how to parse HID based on proto */
				  (yyval.blk).q = (yyvsp[-1].blk).q;
				  if ((yyval.blk).q.addr == Q_PORT)
				  	bpf_error("'port' modifier applied to ip host");
				  else if ((yyval.blk).q.addr == Q_PORTRANGE)
				  	bpf_error("'portrange' modifier applied to ip host");
				  else if ((yyval.blk).q.addr == Q_PROTO)
				  	bpf_error("'proto' modifier applied to ip host");
				  else if ((yyval.blk).q.addr == Q_PROTOCHAIN)
				  	bpf_error("'protochain' modifier applied to ip host");
				  (yyval.blk).b = gen_ncode((yyvsp[0].s), 0, (yyval.blk).q);
				}
#line 2129 "y.tab.c" /* yacc.c:1646  */
    break;

  case 19:
#line 357 "grammar.y" /* yacc.c:1646  */
    {
#ifdef INET6
				  (yyval.blk).b = gen_mcode6((yyvsp[-2].s), NULL, (yyvsp[0].i),
				    (yyval.blk).q = (yyvsp[-3].blk).q);
#else
				  bpf_error("'ip6addr/prefixlen' not supported "
					"in this configuration");
#endif /*INET6*/
				}
#line 2143 "y.tab.c" /* yacc.c:1646  */
    break;

  case 20:
#line 366 "grammar.y" /* yacc.c:1646  */
    {
#ifdef INET6
				  (yyval.blk).b = gen_mcode6((yyvsp[0].s), 0, 128,
				    (yyval.blk).q = (yyvsp[-1].blk).q);
#else
				  bpf_error("'ip6addr' not supported "
					"in this configuration");
#endif /*INET6*/
				}
#line 2157 "y.tab.c" /* yacc.c:1646  */
    break;

  case 21:
#line 375 "grammar.y" /* yacc.c:1646  */
    { 
				  (yyval.blk).b = gen_ecode((yyvsp[0].e), (yyval.blk).q = (yyvsp[-1].blk).q);
				  /*
				   * $1 was allocated by "pcap_ether_aton()",
				   * so we must free it now that we're done
				   * with it.
				   */
				  free((yyvsp[0].e));
				}
#line 2171 "y.tab.c" /* yacc.c:1646  */
    break;

  case 22:
#line 384 "grammar.y" /* yacc.c:1646  */
    {
				  (yyval.blk).b = gen_acode((yyvsp[0].e), (yyval.blk).q = (yyvsp[-1].blk).q);
				  /*
				   * $1 was allocated by "pcap_ether_aton()",
				   * so we must free it now that we're done
				   * with it.
				   */
				  free((yyvsp[0].e));
				}
#line 2185 "y.tab.c" /* yacc.c:1646  */
    break;

  case 23:
#line 393 "grammar.y" /* yacc.c:1646  */
    { gen_not((yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2191 "y.tab.c" /* yacc.c:1646  */
    break;

  case 24:
#line 395 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk) = (yyvsp[-1].blk); }
#line 2197 "y.tab.c" /* yacc.c:1646  */
    break;

  case 25:
#line 397 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk) = (yyvsp[-1].blk); }
#line 2203 "y.tab.c" /* yacc.c:1646  */
    break;

  case 27:
#line 400 "grammar.y" /* yacc.c:1646  */
    { gen_and((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2209 "y.tab.c" /* yacc.c:1646  */
    break;

  case 28:
#line 401 "grammar.y" /* yacc.c:1646  */
    { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2215 "y.tab.c" /* yacc.c:1646  */
    break;

  case 29:
#line 403 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_ncode(NULL, (bpf_u_int32)(yyvsp[0].i),
						   (yyval.blk).q = (yyvsp[-1].blk).q); }
#line 2222 "y.tab.c" /* yacc.c:1646  */
    break;

  case 32:
#line 408 "grammar.y" /* yacc.c:1646  */
    { gen_not((yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2228 "y.tab.c" /* yacc.c:1646  */
    break;

  case 33:
#line 410 "grammar.y" /* yacc.c:1646  */
    { QSET((yyval.blk).q, (yyvsp[-2].i), (yyvsp[-1].i), (yyvsp[0].i)); }
#line 2234 "y.tab.c" /* yacc.c:1646  */
    break;

  case 34:
#line 411 "grammar.y" /* yacc.c:1646  */
    { QSET((yyval.blk).q, (yyvsp[-1].i), (yyvsp[0].i), Q_DEFAULT); }
#line 2240 "y.tab.c" /* yacc.c:1646  */
    break;

  case 35:
#line 412 "grammar.y" /* yacc.c:1646  */
    { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, (yyvsp[0].i)); }
#line 2246 "y.tab.c" /* yacc.c:1646  */
    break;

  case 36:
#line 413 "grammar.y" /* yacc.c:1646  */
    { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, Q_PROTO); }
#line 2252 "y.tab.c" /* yacc.c:1646  */
    break;

  case 37:
#line 414 "grammar.y" /* yacc.c:1646  */
    { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, Q_PROTOCHAIN); }
#line 2258 "y.tab.c" /* yacc.c:1646  */
    break;

  case 38:
#line 415 "grammar.y" /* yacc.c:1646  */
    { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, (yyvsp[0].i)); }
#line 2264 "y.tab.c" /* yacc.c:1646  */
    break;

  case 39:
#line 417 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk) = (yyvsp[0].blk); }
#line 2270 "y.tab.c" /* yacc.c:1646  */
    break;

  case 40:
#line 418 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = (yyvsp[-1].blk).b; (yyval.blk).q = (yyvsp[-2].blk).q; }
#line 2276 "y.tab.c" /* yacc.c:1646  */
    break;

  case 41:
#line 419 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_proto_abbrev((yyvsp[0].i)); (yyval.blk).q = qerr; }
#line 2282 "y.tab.c" /* yacc.c:1646  */
    break;

  case 42:
#line 420 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_relation((yyvsp[-1].i), (yyvsp[-2].a), (yyvsp[0].a), 0);
				  (yyval.blk).q = qerr; }
#line 2289 "y.tab.c" /* yacc.c:1646  */
    break;

  case 43:
#line 422 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_relation((yyvsp[-1].i), (yyvsp[-2].a), (yyvsp[0].a), 1);
				  (yyval.blk).q = qerr; }
#line 2296 "y.tab.c" /* yacc.c:1646  */
    break;

  case 44:
#line 424 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = (yyvsp[0].rblk); (yyval.blk).q = qerr; }
#line 2302 "y.tab.c" /* yacc.c:1646  */
    break;

  case 45:
#line 425 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_atmtype_abbrev((yyvsp[0].i)); (yyval.blk).q = qerr; }
#line 2308 "y.tab.c" /* yacc.c:1646  */
    break;

  case 46:
#line 426 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_atmmulti_abbrev((yyvsp[0].i)); (yyval.blk).q = qerr; }
#line 2314 "y.tab.c" /* yacc.c:1646  */
    break;

  case 47:
#line 427 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = (yyvsp[0].blk).b; (yyval.blk).q = qerr; }
#line 2320 "y.tab.c" /* yacc.c:1646  */
    break;

  case 48:
#line 428 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_mtp2type_abbrev((yyvsp[0].i)); (yyval.blk).q = qerr; }
#line 2326 "y.tab.c" /* yacc.c:1646  */
    break;

  case 49:
#line 429 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = (yyvsp[0].blk).b; (yyval.blk).q = qerr; }
#line 2332 "y.tab.c" /* yacc.c:1646  */
    break;

  case 51:
#line 433 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_DEFAULT; }
#line 2338 "y.tab.c" /* yacc.c:1646  */
    break;

  case 52:
#line 436 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_SRC; }
#line 2344 "y.tab.c" /* yacc.c:1646  */
    break;

  case 53:
#line 437 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_DST; }
#line 2350 "y.tab.c" /* yacc.c:1646  */
    break;

  case 54:
#line 438 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_OR; }
#line 2356 "y.tab.c" /* yacc.c:1646  */
    break;

  case 55:
#line 439 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_OR; }
#line 2362 "y.tab.c" /* yacc.c:1646  */
    break;

  case 56:
#line 440 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_AND; }
#line 2368 "y.tab.c" /* yacc.c:1646  */
    break;

  case 57:
#line 441 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_AND; }
#line 2374 "y.tab.c" /* yacc.c:1646  */
    break;

  case 58:
#line 442 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ADDR1; }
#line 2380 "y.tab.c" /* yacc.c:1646  */
    break;

  case 59:
#line 443 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ADDR2; }
#line 2386 "y.tab.c" /* yacc.c:1646  */
    break;

  case 60:
#line 444 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ADDR3; }
#line 2392 "y.tab.c" /* yacc.c:1646  */
    break;

  case 61:
#line 445 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ADDR4; }
#line 2398 "y.tab.c" /* yacc.c:1646  */
    break;

  case 62:
#line 446 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_RA; }
#line 2404 "y.tab.c" /* yacc.c:1646  */
    break;

  case 63:
#line 447 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_TA; }
#line 2410 "y.tab.c" /* yacc.c:1646  */
    break;

  case 64:
#line 450 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_HOST; }
#line 2416 "y.tab.c" /* yacc.c:1646  */
    break;

  case 65:
#line 451 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_NET; }
#line 2422 "y.tab.c" /* yacc.c:1646  */
    break;

  case 66:
#line 452 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_PORT; }
#line 2428 "y.tab.c" /* yacc.c:1646  */
    break;

  case 67:
#line 453 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_PORTRANGE; }
#line 2434 "y.tab.c" /* yacc.c:1646  */
    break;

  case 68:
#line 456 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_GATEWAY; }
#line 2440 "y.tab.c" /* yacc.c:1646  */
    break;

  case 69:
#line 458 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_LINK; }
#line 2446 "y.tab.c" /* yacc.c:1646  */
    break;

  case 70:
#line 459 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_IP; }
#line 2452 "y.tab.c" /* yacc.c:1646  */
    break;

  case 71:
#line 460 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ARP; }
#line 2458 "y.tab.c" /* yacc.c:1646  */
    break;

  case 72:
#line 461 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_RARP; }
#line 2464 "y.tab.c" /* yacc.c:1646  */
    break;

  case 73:
#line 462 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_SCTP; }
#line 2470 "y.tab.c" /* yacc.c:1646  */
    break;

  case 74:
#line 463 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_TCP; }
#line 2476 "y.tab.c" /* yacc.c:1646  */
    break;

  case 75:
#line 464 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_UDP; }
#line 2482 "y.tab.c" /* yacc.c:1646  */
    break;

  case 76:
#line 465 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ICMP; }
#line 2488 "y.tab.c" /* yacc.c:1646  */
    break;

  case 77:
#line 466 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_IGMP; }
#line 2494 "y.tab.c" /* yacc.c:1646  */
    break;

  case 78:
#line 467 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_IGRP; }
#line 2500 "y.tab.c" /* yacc.c:1646  */
    break;

  case 79:
#line 468 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_PIM; }
#line 2506 "y.tab.c" /* yacc.c:1646  */
    break;

  case 80:
#line 469 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_VRRP; }
#line 2512 "y.tab.c" /* yacc.c:1646  */
    break;

  case 81:
#line 470 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_CARP; }
#line 2518 "y.tab.c" /* yacc.c:1646  */
    break;

  case 82:
#line 471 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ATALK; }
#line 2524 "y.tab.c" /* yacc.c:1646  */
    break;

  case 83:
#line 472 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_AARP; }
#line 2530 "y.tab.c" /* yacc.c:1646  */
    break;

  case 84:
#line 473 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_DECNET; }
#line 2536 "y.tab.c" /* yacc.c:1646  */
    break;

  case 85:
#line 474 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_LAT; }
#line 2542 "y.tab.c" /* yacc.c:1646  */
    break;

  case 86:
#line 475 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_SCA; }
#line 2548 "y.tab.c" /* yacc.c:1646  */
    break;

  case 87:
#line 476 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_MOPDL; }
#line 2554 "y.tab.c" /* yacc.c:1646  */
    break;

  case 88:
#line 477 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_MOPRC; }
#line 2560 "y.tab.c" /* yacc.c:1646  */
    break;

  case 89:
#line 478 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_IPV6; }
#line 2566 "y.tab.c" /* yacc.c:1646  */
    break;

  case 90:
#line 479 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ICMPV6; }
#line 2572 "y.tab.c" /* yacc.c:1646  */
    break;

  case 91:
#line 480 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_AH; }
#line 2578 "y.tab.c" /* yacc.c:1646  */
    break;

  case 92:
#line 481 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ESP; }
#line 2584 "y.tab.c" /* yacc.c:1646  */
    break;

  case 93:
#line 482 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISO; }
#line 2590 "y.tab.c" /* yacc.c:1646  */
    break;

  case 94:
#line 483 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ESIS; }
#line 2596 "y.tab.c" /* yacc.c:1646  */
    break;

  case 95:
#line 484 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS; }
#line 2602 "y.tab.c" /* yacc.c:1646  */
    break;

  case 96:
#line 485 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_L1; }
#line 2608 "y.tab.c" /* yacc.c:1646  */
    break;

  case 97:
#line 486 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_L2; }
#line 2614 "y.tab.c" /* yacc.c:1646  */
    break;

  case 98:
#line 487 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_IIH; }
#line 2620 "y.tab.c" /* yacc.c:1646  */
    break;

  case 99:
#line 488 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_LSP; }
#line 2626 "y.tab.c" /* yacc.c:1646  */
    break;

  case 100:
#line 489 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_SNP; }
#line 2632 "y.tab.c" /* yacc.c:1646  */
    break;

  case 101:
#line 490 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_PSNP; }
#line 2638 "y.tab.c" /* yacc.c:1646  */
    break;

  case 102:
#line 491 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_CSNP; }
#line 2644 "y.tab.c" /* yacc.c:1646  */
    break;

  case 103:
#line 492 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_CLNP; }
#line 2650 "y.tab.c" /* yacc.c:1646  */
    break;

  case 104:
#line 493 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_STP; }
#line 2656 "y.tab.c" /* yacc.c:1646  */
    break;

  case 105:
#line 494 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_IPX; }
#line 2662 "y.tab.c" /* yacc.c:1646  */
    break;

  case 106:
#line 495 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_NETBEUI; }
#line 2668 "y.tab.c" /* yacc.c:1646  */
    break;

  case 107:
#line 496 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_RADIO; }
#line 2674 "y.tab.c" /* yacc.c:1646  */
    break;

  case 108:
#line 498 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_broadcast((yyvsp[-1].i)); }
#line 2680 "y.tab.c" /* yacc.c:1646  */
    break;

  case 109:
#line 499 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_multicast((yyvsp[-1].i)); }
#line 2686 "y.tab.c" /* yacc.c:1646  */
    break;

  case 110:
#line 500 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_less((yyvsp[0].i)); }
#line 2692 "y.tab.c" /* yacc.c:1646  */
    break;

  case 111:
#line 501 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_greater((yyvsp[0].i)); }
#line 2698 "y.tab.c" /* yacc.c:1646  */
    break;

  case 112:
#line 502 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_byteop((yyvsp[-1].i), (yyvsp[-2].i), (yyvsp[0].i)); }
#line 2704 "y.tab.c" /* yacc.c:1646  */
    break;

  case 113:
#line 503 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_inbound(0); }
#line 2710 "y.tab.c" /* yacc.c:1646  */
    break;

  case 114:
#line 504 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_inbound(1); }
#line 2716 "y.tab.c" /* yacc.c:1646  */
    break;

  case 115:
#line 505 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_vlan((yyvsp[0].i)); }
#line 2722 "y.tab.c" /* yacc.c:1646  */
    break;

  case 116:
#line 506 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_vlan(-1); }
#line 2728 "y.tab.c" /* yacc.c:1646  */
    break;

  case 117:
#line 507 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_mpls((yyvsp[0].i)); }
#line 2734 "y.tab.c" /* yacc.c:1646  */
    break;

  case 118:
#line 508 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_mpls(-1); }
#line 2740 "y.tab.c" /* yacc.c:1646  */
    break;

  case 119:
#line 509 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_pppoed(); }
#line 2746 "y.tab.c" /* yacc.c:1646  */
    break;

  case 120:
#line 510 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_pppoes((yyvsp[0].i)); }
#line 2752 "y.tab.c" /* yacc.c:1646  */
    break;

  case 121:
#line 511 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_pppoes(-1); }
#line 2758 "y.tab.c" /* yacc.c:1646  */
    break;

  case 122:
#line 512 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = (yyvsp[0].rblk); }
#line 2764 "y.tab.c" /* yacc.c:1646  */
    break;

  case 123:
#line 513 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = (yyvsp[0].rblk); }
#line 2770 "y.tab.c" /* yacc.c:1646  */
    break;

  case 124:
#line 516 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_pf_ifname((yyvsp[0].s)); }
#line 2776 "y.tab.c" /* yacc.c:1646  */
    break;

  case 125:
#line 517 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_pf_ruleset((yyvsp[0].s)); }
#line 2782 "y.tab.c" /* yacc.c:1646  */
    break;

  case 126:
#line 518 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_pf_rnr((yyvsp[0].i)); }
#line 2788 "y.tab.c" /* yacc.c:1646  */
    break;

  case 127:
#line 519 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_pf_srnr((yyvsp[0].i)); }
#line 2794 "y.tab.c" /* yacc.c:1646  */
    break;

  case 128:
#line 520 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_pf_reason((yyvsp[0].i)); }
#line 2800 "y.tab.c" /* yacc.c:1646  */
    break;

  case 129:
#line 521 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_pf_action((yyvsp[0].i)); }
#line 2806 "y.tab.c" /* yacc.c:1646  */
    break;

  case 130:
#line 525 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_p80211_type((yyvsp[-2].i) | (yyvsp[0].i),
					IEEE80211_FC0_TYPE_MASK |
					IEEE80211_FC0_SUBTYPE_MASK);
				}
#line 2815 "y.tab.c" /* yacc.c:1646  */
    break;

  case 131:
#line 529 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_p80211_type((yyvsp[0].i),
					IEEE80211_FC0_TYPE_MASK);
				}
#line 2823 "y.tab.c" /* yacc.c:1646  */
    break;

  case 132:
#line 532 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_p80211_type((yyvsp[0].i),
					IEEE80211_FC0_TYPE_MASK |
					IEEE80211_FC0_SUBTYPE_MASK);
				}
#line 2832 "y.tab.c" /* yacc.c:1646  */
    break;

  case 133:
#line 536 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = gen_p80211_fcdir((yyvsp[0].i)); }
#line 2838 "y.tab.c" /* yacc.c:1646  */
    break;

  case 135:
#line 540 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = str2tok((yyvsp[0].s), ieee80211_types);
				  if ((yyval.i) == -1)
				  	bpf_error("unknown 802.11 type name");
				}
#line 2847 "y.tab.c" /* yacc.c:1646  */
    break;

  case 137:
#line 547 "grammar.y" /* yacc.c:1646  */
    { const struct tok *types = NULL;
				  int i;
				  for (i = 0;; i++) {
				  	if (ieee80211_type_subtypes[i].tok == NULL) {
				  		/* Ran out of types */
						bpf_error("unknown 802.11 type");
						break;
					}
					if ((yyvsp[(-1) - (1)].i) == ieee80211_type_subtypes[i].type) {
						types = ieee80211_type_subtypes[i].tok;
						break;
					}
				  }

				  (yyval.i) = str2tok((yyvsp[0].s), types);
				  if ((yyval.i) == -1)
					bpf_error("unknown 802.11 subtype name");
				}
#line 2870 "y.tab.c" /* yacc.c:1646  */
    break;

  case 138:
#line 567 "grammar.y" /* yacc.c:1646  */
    { int i;
				  for (i = 0;; i++) {
				  	if (ieee80211_type_subtypes[i].tok == NULL) {
				  		/* Ran out of types */
						bpf_error("unknown 802.11 type name");
						break;
					}
					(yyval.i) = str2tok((yyvsp[0].s), ieee80211_type_subtypes[i].tok);
					if ((yyval.i) != -1) {
						(yyval.i) |= ieee80211_type_subtypes[i].type;
						break;
					}
				  }
				}
#line 2889 "y.tab.c" /* yacc.c:1646  */
    break;

  case 140:
#line 584 "grammar.y" /* yacc.c:1646  */
    { if (pcap_strcasecmp((yyvsp[0].s), "nods") == 0)
					(yyval.i) = IEEE80211_FC1_DIR_NODS;
				  else if (pcap_strcasecmp((yyvsp[0].s), "tods") == 0)
					(yyval.i) = IEEE80211_FC1_DIR_TODS;
				  else if (pcap_strcasecmp((yyvsp[0].s), "fromds") == 0)
					(yyval.i) = IEEE80211_FC1_DIR_FROMDS;
				  else if (pcap_strcasecmp((yyvsp[0].s), "dstods") == 0)
					(yyval.i) = IEEE80211_FC1_DIR_DSTODS;
				  else
					bpf_error("unknown 802.11 direction");
				}
#line 2905 "y.tab.c" /* yacc.c:1646  */
    break;

  case 141:
#line 597 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = (yyvsp[0].i); }
#line 2911 "y.tab.c" /* yacc.c:1646  */
    break;

  case 142:
#line 598 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = pfreason_to_num((yyvsp[0].s)); }
#line 2917 "y.tab.c" /* yacc.c:1646  */
    break;

  case 143:
#line 601 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = pfaction_to_num((yyvsp[0].s)); }
#line 2923 "y.tab.c" /* yacc.c:1646  */
    break;

  case 144:
#line 604 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = BPF_JGT; }
#line 2929 "y.tab.c" /* yacc.c:1646  */
    break;

  case 145:
#line 605 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = BPF_JGE; }
#line 2935 "y.tab.c" /* yacc.c:1646  */
    break;

  case 146:
#line 606 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = BPF_JEQ; }
#line 2941 "y.tab.c" /* yacc.c:1646  */
    break;

  case 147:
#line 608 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = BPF_JGT; }
#line 2947 "y.tab.c" /* yacc.c:1646  */
    break;

  case 148:
#line 609 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = BPF_JGE; }
#line 2953 "y.tab.c" /* yacc.c:1646  */
    break;

  case 149:
#line 610 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = BPF_JEQ; }
#line 2959 "y.tab.c" /* yacc.c:1646  */
    break;

  case 150:
#line 612 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_loadi((yyvsp[0].i)); }
#line 2965 "y.tab.c" /* yacc.c:1646  */
    break;

  case 152:
#line 615 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_load((yyvsp[-3].i), (yyvsp[-1].a), 1); }
#line 2971 "y.tab.c" /* yacc.c:1646  */
    break;

  case 153:
#line 616 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_load((yyvsp[-5].i), (yyvsp[-3].a), (yyvsp[-1].i)); }
#line 2977 "y.tab.c" /* yacc.c:1646  */
    break;

  case 154:
#line 617 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_arth(BPF_ADD, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 2983 "y.tab.c" /* yacc.c:1646  */
    break;

  case 155:
#line 618 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_arth(BPF_SUB, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 2989 "y.tab.c" /* yacc.c:1646  */
    break;

  case 156:
#line 619 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_arth(BPF_MUL, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 2995 "y.tab.c" /* yacc.c:1646  */
    break;

  case 157:
#line 620 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_arth(BPF_DIV, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3001 "y.tab.c" /* yacc.c:1646  */
    break;

  case 158:
#line 621 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_arth(BPF_AND, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3007 "y.tab.c" /* yacc.c:1646  */
    break;

  case 159:
#line 622 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_arth(BPF_OR, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3013 "y.tab.c" /* yacc.c:1646  */
    break;

  case 160:
#line 623 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_arth(BPF_LSH, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3019 "y.tab.c" /* yacc.c:1646  */
    break;

  case 161:
#line 624 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_arth(BPF_RSH, (yyvsp[-2].a), (yyvsp[0].a)); }
#line 3025 "y.tab.c" /* yacc.c:1646  */
    break;

  case 162:
#line 625 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_neg((yyvsp[0].a)); }
#line 3031 "y.tab.c" /* yacc.c:1646  */
    break;

  case 163:
#line 626 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = (yyvsp[-1].a); }
#line 3037 "y.tab.c" /* yacc.c:1646  */
    break;

  case 164:
#line 627 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = gen_loadlen(); }
#line 3043 "y.tab.c" /* yacc.c:1646  */
    break;

  case 165:
#line 629 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = '&'; }
#line 3049 "y.tab.c" /* yacc.c:1646  */
    break;

  case 166:
#line 630 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = '|'; }
#line 3055 "y.tab.c" /* yacc.c:1646  */
    break;

  case 167:
#line 631 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = '<'; }
#line 3061 "y.tab.c" /* yacc.c:1646  */
    break;

  case 168:
#line 632 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = '>'; }
#line 3067 "y.tab.c" /* yacc.c:1646  */
    break;

  case 169:
#line 633 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = '='; }
#line 3073 "y.tab.c" /* yacc.c:1646  */
    break;

  case 171:
#line 636 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = (yyvsp[-1].i); }
#line 3079 "y.tab.c" /* yacc.c:1646  */
    break;

  case 172:
#line 638 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_LANE; }
#line 3085 "y.tab.c" /* yacc.c:1646  */
    break;

  case 173:
#line 639 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_LLC; }
#line 3091 "y.tab.c" /* yacc.c:1646  */
    break;

  case 174:
#line 640 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_METAC;	}
#line 3097 "y.tab.c" /* yacc.c:1646  */
    break;

  case 175:
#line 641 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_BCC; }
#line 3103 "y.tab.c" /* yacc.c:1646  */
    break;

  case 176:
#line 642 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_OAMF4EC; }
#line 3109 "y.tab.c" /* yacc.c:1646  */
    break;

  case 177:
#line 643 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_OAMF4SC; }
#line 3115 "y.tab.c" /* yacc.c:1646  */
    break;

  case 178:
#line 644 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_SC; }
#line 3121 "y.tab.c" /* yacc.c:1646  */
    break;

  case 179:
#line 645 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_ILMIC; }
#line 3127 "y.tab.c" /* yacc.c:1646  */
    break;

  case 180:
#line 647 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_OAM; }
#line 3133 "y.tab.c" /* yacc.c:1646  */
    break;

  case 181:
#line 648 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_OAMF4; }
#line 3139 "y.tab.c" /* yacc.c:1646  */
    break;

  case 182:
#line 649 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_CONNECTMSG; }
#line 3145 "y.tab.c" /* yacc.c:1646  */
    break;

  case 183:
#line 650 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_METACONNECT; }
#line 3151 "y.tab.c" /* yacc.c:1646  */
    break;

  case 184:
#line 653 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).atmfieldtype = A_VPI; }
#line 3157 "y.tab.c" /* yacc.c:1646  */
    break;

  case 185:
#line 654 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).atmfieldtype = A_VCI; }
#line 3163 "y.tab.c" /* yacc.c:1646  */
    break;

  case 187:
#line 657 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_atmfield_code((yyvsp[-2].blk).atmfieldtype, (bpf_int32)(yyvsp[0].i), (bpf_u_int32)(yyvsp[-1].i), 0); }
#line 3169 "y.tab.c" /* yacc.c:1646  */
    break;

  case 188:
#line 658 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_atmfield_code((yyvsp[-2].blk).atmfieldtype, (bpf_int32)(yyvsp[0].i), (bpf_u_int32)(yyvsp[-1].i), 1); }
#line 3175 "y.tab.c" /* yacc.c:1646  */
    break;

  case 189:
#line 659 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = (yyvsp[-1].blk).b; (yyval.blk).q = qerr; }
#line 3181 "y.tab.c" /* yacc.c:1646  */
    break;

  case 190:
#line 661 "grammar.y" /* yacc.c:1646  */
    {
	(yyval.blk).atmfieldtype = (yyvsp[-1].blk).atmfieldtype;
	if ((yyval.blk).atmfieldtype == A_VPI ||
	    (yyval.blk).atmfieldtype == A_VCI)
		(yyval.blk).b = gen_atmfield_code((yyval.blk).atmfieldtype, (bpf_int32) (yyvsp[0].i), BPF_JEQ, 0);
	}
#line 3192 "y.tab.c" /* yacc.c:1646  */
    break;

  case 192:
#line 669 "grammar.y" /* yacc.c:1646  */
    { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 3198 "y.tab.c" /* yacc.c:1646  */
    break;

  case 193:
#line 672 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = M_FISU; }
#line 3204 "y.tab.c" /* yacc.c:1646  */
    break;

  case 194:
#line 673 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = M_LSSU; }
#line 3210 "y.tab.c" /* yacc.c:1646  */
    break;

  case 195:
#line 674 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = M_MSU; }
#line 3216 "y.tab.c" /* yacc.c:1646  */
    break;

  case 196:
#line 675 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = MH_FISU; }
#line 3222 "y.tab.c" /* yacc.c:1646  */
    break;

  case 197:
#line 676 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = MH_LSSU; }
#line 3228 "y.tab.c" /* yacc.c:1646  */
    break;

  case 198:
#line 677 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = MH_MSU; }
#line 3234 "y.tab.c" /* yacc.c:1646  */
    break;

  case 199:
#line 680 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = M_SIO; }
#line 3240 "y.tab.c" /* yacc.c:1646  */
    break;

  case 200:
#line 681 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = M_OPC; }
#line 3246 "y.tab.c" /* yacc.c:1646  */
    break;

  case 201:
#line 682 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = M_DPC; }
#line 3252 "y.tab.c" /* yacc.c:1646  */
    break;

  case 202:
#line 683 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = M_SLS; }
#line 3258 "y.tab.c" /* yacc.c:1646  */
    break;

  case 203:
#line 684 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = MH_SIO; }
#line 3264 "y.tab.c" /* yacc.c:1646  */
    break;

  case 204:
#line 685 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = MH_OPC; }
#line 3270 "y.tab.c" /* yacc.c:1646  */
    break;

  case 205:
#line 686 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = MH_DPC; }
#line 3276 "y.tab.c" /* yacc.c:1646  */
    break;

  case 206:
#line 687 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = MH_SLS; }
#line 3282 "y.tab.c" /* yacc.c:1646  */
    break;

  case 208:
#line 690 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_mtp3field_code((yyvsp[-2].blk).mtp3fieldtype, (u_int)(yyvsp[0].i), (u_int)(yyvsp[-1].i), 0); }
#line 3288 "y.tab.c" /* yacc.c:1646  */
    break;

  case 209:
#line 691 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = gen_mtp3field_code((yyvsp[-2].blk).mtp3fieldtype, (u_int)(yyvsp[0].i), (u_int)(yyvsp[-1].i), 1); }
#line 3294 "y.tab.c" /* yacc.c:1646  */
    break;

  case 210:
#line 692 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = (yyvsp[-1].blk).b; (yyval.blk).q = qerr; }
#line 3300 "y.tab.c" /* yacc.c:1646  */
    break;

  case 211:
#line 694 "grammar.y" /* yacc.c:1646  */
    {
	(yyval.blk).mtp3fieldtype = (yyvsp[-1].blk).mtp3fieldtype;
	if ((yyval.blk).mtp3fieldtype == M_SIO ||
	    (yyval.blk).mtp3fieldtype == M_OPC ||
	    (yyval.blk).mtp3fieldtype == M_DPC ||
	    (yyval.blk).mtp3fieldtype == M_SLS ||
	    (yyval.blk).mtp3fieldtype == MH_SIO ||
	    (yyval.blk).mtp3fieldtype == MH_OPC ||
	    (yyval.blk).mtp3fieldtype == MH_DPC ||
	    (yyval.blk).mtp3fieldtype == MH_SLS)
		(yyval.blk).b = gen_mtp3field_code((yyval.blk).mtp3fieldtype, (u_int) (yyvsp[0].i), BPF_JEQ, 0);
	}
#line 3317 "y.tab.c" /* yacc.c:1646  */
    break;

  case 213:
#line 708 "grammar.y" /* yacc.c:1646  */
    { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 3323 "y.tab.c" /* yacc.c:1646  */
    break;


#line 3327 "y.tab.c" /* yacc.c:1646  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 710 "grammar.y" /* yacc.c:1906  */

