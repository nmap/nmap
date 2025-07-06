/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

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
#define YYBISON_VERSION "3.0.4"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

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


/* Copy the first part of user declarations.  */
#line 47 "grammar.y" /* yacc.c:339  */

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

#include <config.h>

/*
 * grammar.h requires gencode.h and sometimes breaks in a polluted namespace
 * (see ftmacros.h), so include it early.
 */
#include "gencode.h"
#include "grammar.h"

#include <stdlib.h>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>

#if __STDC__
struct mbuf;
struct rtentry;
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* _WIN32 */

#include <stdio.h>

#include "diag-control.h"

#include "pcap-int.h"

#include "scanner.h"

#include "llc.h"
#include "ieee80211.h"
#include "pflog.h"
#include <pcap/namedb.h>

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

/*
 * Work around some bugs in Berkeley YACC prior to the 2017-07-09
 * release.
 *
 * The 2005-05-05 release was the first one to define YYPATCH, so
 * we treat any release that either 1) doesn't define YYPATCH or
 * 2) defines it to a value < 20170709 as being buggy.
 */
#if defined(YYBYACC) && (!defined(YYPATCH) || YYPATCH < 20170709)
/*
 * Both Berkeley YACC and Bison define yydebug (under whatever name
 * it has) as a global, but Bison does so only if YYDEBUG is defined.
 * Berkeley YACC, prior to the 2017-07-09 release, defines it even if
 * YYDEBUG isn't defined; declare it here to suppress a warning.  The
 * 2017-07-09 release fixes that.
 */
#if !defined(YYDEBUG)
extern int yydebug;
#endif

/*
 * In Berkeley YACC, prior to the 2017-07-09 release, yynerrs (under
 * whatever name it has) is global, even if it's building a reentrant
 * parser.  In Bison, and in the Berkeley YACC 2017-07-09 release and
 * later, it's local in reentrant parsers.
 *
 * Declare it to squelch a warning.
 */
extern int yynerrs;
#endif

#define QSET(q, p, d, a) (q).proto = (unsigned char)(p),\
			 (q).dir = (unsigned char)(d),\
			 (q).addr = (unsigned char)(a)

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
static const struct tok llc_s_subtypes[] = {
	{ LLC_RR, "rr" },
	{ LLC_RNR, "rnr" },
	{ LLC_REJ, "rej" },
	{ 0, NULL }
};
static const struct tok llc_u_subtypes[] = {
	{ LLC_UI, "ui" },
	{ LLC_UA, "ua" },
	{ LLC_DISC, "disc" },
	{ LLC_DM, "dm" },
	{ LLC_SABME, "sabme" },
	{ LLC_TEST, "test" },
	{ LLC_XID, "xid" },
	{ LLC_FRMR, "frmr" },
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
		if (pcapint_strcasecmp(toks[i].s, str) == 0) {
			/*
			 * Just in case somebody is using this to
			 * generate values of -1/0xFFFFFFFF.
			 * That won't work, as it's indistinguishable
			 * from an error.
			 */
			if (toks[i].v == -1)
				abort();
			return (toks[i].v);
		}
	}
	return (-1);
}

static const struct qual qerr = { Q_UNDEF, Q_UNDEF, Q_UNDEF, Q_UNDEF };

static void
yyerror(void *yyscanner _U_, compiler_state_t *cstate, const char *msg)
{
	bpf_set_error(cstate, "can't parse filter expression: %s", msg);
}

static const struct tok pflog_reasons[] = {
	{ PFRES_MATCH,		"match" },
	{ PFRES_BADOFF,		"bad-offset" },
	{ PFRES_FRAG,		"fragment" },
	{ PFRES_SHORT,		"short" },
	{ PFRES_NORM,		"normalize" },
	{ PFRES_MEMORY,		"memory" },
	{ PFRES_TS,		"bad-timestamp" },
	{ PFRES_CONGEST,	"congestion" },
	{ PFRES_IPOPTIONS,	"ip-option" },
	{ PFRES_PROTCKSUM,	"proto-cksum" },
	{ PFRES_BADSTATE,	"state-mismatch" },
	{ PFRES_STATEINS,	"state-insert" },
	{ PFRES_MAXSTATES,	"state-limit" },
	{ PFRES_SRCLIMIT,	"src-limit" },
	{ PFRES_SYNPROXY,	"synproxy" },
#if defined(__FreeBSD__)
	{ PFRES_MAPFAILED,	"map-failed" },
#elif defined(__NetBSD__)
	{ PFRES_STATELOCKED,	"state-locked" },
#elif defined(__OpenBSD__)
	{ PFRES_TRANSLATE,	"translate" },
	{ PFRES_NOROUTE,	"no-route" },
#elif defined(__APPLE__)
	{ PFRES_DUMMYNET,	"dummynet" },
#endif
	{ 0, NULL }
};

static int
pfreason_to_num(compiler_state_t *cstate, const char *reason)
{
	int i;

	i = str2tok(reason, pflog_reasons);
	if (i == -1)
		bpf_set_error(cstate, "unknown PF reason \"%s\"", reason);
	return (i);
}

static const struct tok pflog_actions[] = {
	{ PF_PASS,		"pass" },
	{ PF_PASS,		"accept" },	/* alias for "pass" */
	{ PF_DROP,		"drop" },
	{ PF_DROP,		"block" },	/* alias for "drop" */
	{ PF_SCRUB,		"scrub" },
	{ PF_NOSCRUB,		"noscrub" },
	{ PF_NAT,		"nat" },
	{ PF_NONAT,		"nonat" },
	{ PF_BINAT,		"binat" },
	{ PF_NOBINAT,		"nobinat" },
	{ PF_RDR,		"rdr" },
	{ PF_NORDR,		"nordr" },
	{ PF_SYNPROXY_DROP,	"synproxy-drop" },
#if defined(__FreeBSD__)
	{ PF_DEFER,		"defer" },
#elif defined(__OpenBSD__)
	{ PF_DEFER,		"defer" },
	{ PF_MATCH,		"match" },
	{ PF_DIVERT,		"divert" },
	{ PF_RT,		"rt" },
	{ PF_AFRT,		"afrt" },
#elif defined(__APPLE__)
	{ PF_DUMMYNET,		"dummynet" },
	{ PF_NODUMMYNET,	"nodummynet" },
	{ PF_NAT64,		"nat64" },
	{ PF_NONAT64,		"nonat64" },
#endif
	{ 0, NULL },
};

static int
pfaction_to_num(compiler_state_t *cstate, const char *action)
{
	int i;

	i = str2tok(action, pflog_actions);
	if (i == -1)
		bpf_set_error(cstate, "unknown PF action \"%s\"", action);
	return (i);
}

/*
 * For calls that might return an "an error occurred" value.
 */
#define CHECK_INT_VAL(val)	if (val == -1) YYABORT
#define CHECK_PTR_VAL(val)	if (val == NULL) YYABORT

DIAG_OFF_BISON_BYACC

#line 382 "grammar.c" /* yacc.c:339  */

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
   by #include "grammar.h".  */
#ifndef YY_PCAP_GRAMMAR_H_INCLUDED
# define YY_PCAP_GRAMMAR_H_INCLUDED
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
    IFINDEX = 295,
    PF_IFNAME = 296,
    PF_RSET = 297,
    PF_RNR = 298,
    PF_SRNR = 299,
    PF_REASON = 300,
    PF_ACTION = 301,
    TYPE = 302,
    SUBTYPE = 303,
    DIR = 304,
    ADDR1 = 305,
    ADDR2 = 306,
    ADDR3 = 307,
    ADDR4 = 308,
    RA = 309,
    TA = 310,
    LINK = 311,
    GEQ = 312,
    LEQ = 313,
    NEQ = 314,
    ID = 315,
    EID = 316,
    HID = 317,
    HID6 = 318,
    AID = 319,
    LSH = 320,
    RSH = 321,
    LEN = 322,
    IPV6 = 323,
    ICMPV6 = 324,
    AH = 325,
    ESP = 326,
    VLAN = 327,
    MPLS = 328,
    PPPOED = 329,
    PPPOES = 330,
    GENEVE = 331,
    ISO = 332,
    ESIS = 333,
    CLNP = 334,
    ISIS = 335,
    L1 = 336,
    L2 = 337,
    IIH = 338,
    LSP = 339,
    SNP = 340,
    CSNP = 341,
    PSNP = 342,
    STP = 343,
    IPX = 344,
    NETBEUI = 345,
    LANE = 346,
    LLC = 347,
    METAC = 348,
    BCC = 349,
    SC = 350,
    ILMIC = 351,
    OAMF4EC = 352,
    OAMF4SC = 353,
    OAM = 354,
    OAMF4 = 355,
    CONNECTMSG = 356,
    METACONNECT = 357,
    VPI = 358,
    VCI = 359,
    RADIO = 360,
    FISU = 361,
    LSSU = 362,
    MSU = 363,
    HFISU = 364,
    HLSSU = 365,
    HMSU = 366,
    SIO = 367,
    OPC = 368,
    DPC = 369,
    SLS = 370,
    HSIO = 371,
    HOPC = 372,
    HDPC = 373,
    HSLS = 374,
    LEX_ERROR = 375,
    OR = 376,
    AND = 377,
    UMINUS = 378
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 357 "grammar.y" /* yacc.c:355  */

	int i;
	bpf_u_int32 h;
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

#line 561 "grammar.c" /* yacc.c:355  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int pcap_parse (void *yyscanner, compiler_state_t *cstate);

#endif /* !YY_PCAP_GRAMMAR_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 577 "grammar.c" /* yacc.c:358  */

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
#define YYLAST   800

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  141
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  47
/* YYNRULES -- Number of rules.  */
#define YYNRULES  221
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  296

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   378

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   123,     2,     2,     2,   139,   125,     2,
     132,   131,   128,   126,     2,   127,     2,   129,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,   138,     2,
     135,   134,   133,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   136,     2,   137,   140,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,   124,     2,     2,     2,     2,     2,
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
     115,   116,   117,   118,   119,   120,   121,   122,   130
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   431,   431,   443,   445,   447,   448,   449,   450,   451,
     453,   455,   457,   458,   460,   462,   463,   482,   501,   520,
     545,   570,   571,   572,   574,   576,   578,   579,   580,   582,
     584,   586,   587,   589,   590,   591,   592,   593,   601,   603,
     604,   605,   606,   608,   610,   611,   612,   613,   614,   615,
     618,   619,   622,   623,   624,   625,   626,   627,   628,   629,
     630,   631,   632,   633,   636,   637,   638,   639,   642,   644,
     645,   646,   647,   648,   649,   650,   651,   652,   653,   654,
     655,   656,   657,   658,   659,   660,   661,   662,   663,   664,
     665,   666,   667,   668,   669,   670,   671,   672,   673,   674,
     675,   676,   677,   678,   679,   680,   681,   682,   684,   685,
     686,   687,   688,   689,   690,   691,   692,   693,   694,   695,
     696,   697,   698,   699,   700,   701,   702,   703,   706,   707,
     708,   709,   710,   711,   714,   719,   722,   726,   729,   735,
     744,   750,   773,   790,   791,   815,   818,   819,   835,   836,
     839,   842,   843,   844,   846,   847,   848,   850,   851,   853,
     854,   855,   856,   857,   858,   859,   860,   861,   862,   863,
     864,   865,   866,   867,   869,   870,   871,   872,   873,   875,
     876,   878,   879,   880,   881,   882,   883,   884,   886,   887,
     888,   889,   892,   893,   895,   896,   897,   898,   900,   907,
     908,   911,   912,   913,   914,   915,   916,   919,   920,   921,
     922,   923,   924,   925,   926,   928,   929,   930,   931,   933,
     946,   947
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
  "OUTBOUND", "IFINDEX", "PF_IFNAME", "PF_RSET", "PF_RNR", "PF_SRNR",
  "PF_REASON", "PF_ACTION", "TYPE", "SUBTYPE", "DIR", "ADDR1", "ADDR2",
  "ADDR3", "ADDR4", "RA", "TA", "LINK", "GEQ", "LEQ", "NEQ", "ID", "EID",
  "HID", "HID6", "AID", "LSH", "RSH", "LEN", "IPV6", "ICMPV6", "AH", "ESP",
  "VLAN", "MPLS", "PPPOED", "PPPOES", "GENEVE", "ISO", "ESIS", "CLNP",
  "ISIS", "L1", "L2", "IIH", "LSP", "SNP", "CSNP", "PSNP", "STP", "IPX",
  "NETBEUI", "LANE", "LLC", "METAC", "BCC", "SC", "ILMIC", "OAMF4EC",
  "OAMF4SC", "OAM", "OAMF4", "CONNECTMSG", "METACONNECT", "VPI", "VCI",
  "RADIO", "FISU", "LSSU", "MSU", "HFISU", "HLSSU", "HMSU", "SIO", "OPC",
  "DPC", "SLS", "HSIO", "HOPC", "HDPC", "HSLS", "LEX_ERROR", "OR", "AND",
  "'!'", "'|'", "'&'", "'+'", "'-'", "'*'", "'/'", "UMINUS", "')'", "'('",
  "'>'", "'='", "'<'", "'['", "']'", "':'", "'%'", "'^'", "$accept",
  "prog", "null", "expr", "and", "or", "id", "nid", "not", "paren", "pid",
  "qid", "term", "head", "rterm", "pqual", "dqual", "aqual", "ndaqual",
  "pname", "other", "pfvar", "p80211", "type", "subtype", "type_subtype",
  "pllc", "dir", "reason", "action", "relop", "irelop", "arth", "narth",
  "byteop", "pnum", "atmtype", "atmmultitype", "atmfield", "atmvalue",
  "atmfieldvalue", "atmlistvalue", "mtp2type", "mtp3field", "mtp3value",
  "mtp3fieldvalue", "mtp3listvalue", YY_NULLPTR
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
     375,   376,   377,    33,   124,    38,    43,    45,    42,    47,
     378,    41,    40,    62,    61,    60,    91,    93,    58,    37,
      94
};
# endif

#define YYPACT_NINF -217

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-217)))

#define YYTABLE_NINF -42

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
    -217,    28,   223,  -217,    13,    18,    21,  -217,  -217,  -217,
    -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,
    -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,    41,
     -30,    24,    51,    79,   -25,    26,  -217,  -217,  -217,  -217,
    -217,  -217,   -24,   -24,  -217,   -24,   -24,  -217,  -217,  -217,
    -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,
    -217,  -217,   -23,  -217,  -217,  -217,  -217,  -217,  -217,  -217,
    -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,
    -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,
    -217,   576,  -217,   -50,   459,   459,  -217,    19,  -217,   745,
       3,  -217,  -217,  -217,   558,  -217,  -217,  -217,  -217,    -5,
    -217,    39,  -217,  -217,   -14,  -217,  -217,  -217,  -217,  -217,
    -217,  -217,  -217,  -217,  -217,   -24,  -217,  -217,  -217,  -217,
    -217,  -217,   576,  -103,   -49,  -217,  -217,   341,   341,  -217,
    -100,     2,    12,  -217,  -217,    -7,    -3,  -217,  -217,  -217,
      19,    19,  -217,    -4,    31,  -217,  -217,  -217,  -217,  -217,
    -217,  -217,  -217,  -217,   -22,    78,   -18,  -217,  -217,  -217,
    -217,  -217,  -217,    60,  -217,  -217,  -217,   576,  -217,  -217,
    -217,   576,   576,   576,   576,   576,   576,   576,   576,  -217,
    -217,  -217,   576,   576,   576,   576,  -217,   125,   126,   127,
    -217,  -217,  -217,   132,   133,   144,  -217,  -217,  -217,  -217,
    -217,  -217,  -217,   145,    12,   602,  -217,   341,   341,  -217,
      10,  -217,  -217,  -217,  -217,  -217,   123,   149,   150,  -217,
    -217,    63,   -50,    12,   191,   192,   194,   195,  -217,  -217,
     151,  -217,  -217,  -217,  -217,  -217,  -217,   585,    64,    64,
     607,    49,   -66,   -66,   -49,   -49,   602,   602,   602,   602,
    -217,   -97,  -217,  -217,  -217,   -92,  -217,  -217,  -217,   -95,
    -217,  -217,  -217,  -217,    19,    19,  -217,  -217,  -217,  -217,
     -12,  -217,   163,  -217,   125,  -217,   132,  -217,  -217,  -217,
    -217,  -217,    65,  -217,  -217,  -217
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       4,     0,    51,     1,     0,     0,     0,    71,    72,    70,
      73,    74,    75,    76,    77,    78,    79,    80,    81,    82,
      83,    84,    85,    86,    88,    87,   179,   113,   114,     0,
       0,     0,     0,     0,     0,     0,    69,   173,    89,    90,
      91,    92,   117,   119,   120,   122,   124,    93,    94,   103,
      95,    96,    97,    98,    99,   100,   102,   101,   104,   105,
     106,   181,   143,   182,   183,   186,   187,   184,   185,   188,
     189,   190,   191,   192,   193,   107,   201,   202,   203,   204,
     205,   206,   207,   208,   209,   210,   211,   212,   213,   214,
      24,     0,    25,     2,    51,    51,     5,     0,    31,     0,
      50,    44,   125,   127,     0,   158,   157,    45,    46,     0,
      48,     0,   110,   111,     0,   115,   128,   129,   130,   131,
     148,   149,   132,   150,   133,     0,   116,   118,   121,   123,
     145,   144,     0,     0,   171,    11,    10,    51,    51,    32,
       0,   158,   157,    15,    21,    18,    20,    22,    39,    12,
       0,     0,    13,    53,    52,    64,    68,    65,    66,    67,
      36,    37,   108,   109,     0,     0,     0,    58,    59,    60,
      61,    62,    63,    34,    35,    38,   126,     0,   152,   154,
     156,     0,     0,     0,     0,     0,     0,     0,     0,   151,
     153,   155,     0,     0,     0,     0,   198,     0,     0,     0,
      47,   194,   219,     0,     0,     0,    49,   215,   175,   174,
     177,   178,   176,     0,     0,     0,     7,    51,    51,     6,
     157,     9,     8,    40,   172,   180,     0,     0,     0,    23,
      26,    30,     0,    29,     0,     0,     0,     0,   138,   139,
     135,   142,   136,   146,   147,   137,    33,     0,   169,   170,
     167,   166,   161,   162,   163,   164,   165,   168,    42,    43,
     199,     0,   195,   196,   220,     0,   216,   217,   112,   157,
      17,    16,    19,    14,     0,     0,    55,    57,    54,    56,
       0,   159,     0,   197,     0,   218,     0,    27,    28,   140,
     141,   134,     0,   200,   221,   160
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -217,  -217,  -217,   199,   -26,  -216,   -91,  -133,     7,    -2,
    -217,  -217,   -77,  -217,  -217,  -217,  -217,    32,  -217,     9,
    -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,  -217,
     -43,   -34,   -27,   -81,  -217,   -38,  -217,  -217,  -217,  -217,
    -195,  -217,  -217,  -217,  -217,  -180,  -217
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     2,   140,   137,   138,   229,   149,   150,   132,
     231,   232,    96,    97,    98,    99,   173,   174,   175,   133,
     101,   102,   176,   240,   291,   242,   103,   245,   122,   124,
     194,   195,   104,   105,   213,   106,   107,   108,   109,   200,
     201,   261,   110,   111,   206,   207,   265
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      95,   226,   260,   -41,   126,   127,   148,   128,   129,    94,
     -13,   100,   120,    26,   141,   238,   275,   139,   230,   243,
     130,   135,   136,   264,   135,   289,   -29,   -29,     3,   135,
     116,   223,   196,   177,   283,   121,   225,   131,   239,   285,
     125,   125,   244,   125,   125,   284,   216,   221,   290,   286,
     112,   141,   178,   179,   180,   113,    26,   142,   114,   152,
     219,   222,   187,   188,   134,   155,   198,   157,   204,   158,
     159,   135,   136,   192,   193,   199,   202,   205,   115,   143,
     144,   145,   146,   147,   117,   230,   123,   214,   118,   293,
     192,   193,    95,    95,   142,   151,   178,   179,   180,   220,
     220,    94,    94,   100,   100,   215,   294,   197,    92,   203,
     208,   209,   152,   233,   181,   182,   119,   234,   235,   210,
     211,   212,   227,   125,   -41,   -41,   228,    92,   189,   190,
     191,   -13,   -13,   224,   -41,   218,   218,   141,   241,   177,
     139,   -13,    90,   225,   217,   217,   100,   100,   151,   125,
     247,    92,   236,   237,   248,   249,   250,   251,   252,   253,
     254,   255,   196,   262,   263,   256,   257,   258,   259,   202,
     266,    92,   189,   190,   191,   185,   186,   187,   188,   220,
     269,   267,   268,   287,   288,   270,   271,   272,   192,   193,
     185,   186,   187,   188,   273,   276,   277,   278,   279,   280,
     292,    93,   295,   192,   193,   246,   274,     0,     0,     0,
       0,     0,     0,     0,     0,   218,    95,     0,     0,     0,
       0,     0,     0,    -3,   217,   217,   100,   100,     0,     0,
       0,     0,     0,     0,     4,     5,   152,   152,     6,     7,
       8,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,     0,     0,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
       0,     0,   151,   151,     0,     0,     0,     0,     0,    36,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      37,    38,    39,    40,    41,    42,    43,    44,    45,    46,
      47,    48,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    71,    72,    73,    74,    75,    76,
      77,    78,    79,    80,    81,    82,    83,    84,    85,    86,
      87,    88,    89,     0,     0,     0,    90,     0,     0,     0,
      91,     0,     4,     5,     0,    92,     6,     7,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,     0,     0,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    36,     0,     0,
       0,   143,   144,   145,   146,   147,     0,     0,    37,    38,
      39,    40,    41,    42,    43,    44,    45,    46,    47,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,    68,
      69,    70,    71,    72,    73,    74,    75,    76,    77,    78,
      79,    80,    81,    82,    83,    84,    85,    86,    87,    88,
      89,     0,     0,     0,    90,     0,     0,     0,    91,     0,
       4,     5,     0,    92,     6,     7,     8,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,     0,     0,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    36,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    37,    38,    39,    40,
      41,    42,    43,    44,    45,    46,    47,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      61,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      71,    72,    73,    74,    75,    76,    77,    78,    79,    80,
      81,    82,    83,    84,    85,    86,    87,    88,    89,     0,
       0,     0,    90,     0,     0,     0,    91,     0,     0,     0,
       0,    92,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,     0,     0,    26,     0,   178,   179,   180,     0,     0,
       0,     0,     0,   181,   182,     0,     0,     0,     0,     0,
       0,     0,    36,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    37,    38,    39,    40,    41,     0,     0,
     181,   182,     0,    47,    48,    49,    50,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    60,   181,   182,     0,
       0,     0,   181,   182,     0,     0,     0,     0,     0,     0,
       0,    75,   183,   184,   185,   186,   187,   188,     0,     0,
       0,   189,   190,   191,     0,     0,     0,   192,   193,     0,
       0,     0,     0,    91,     0,     0,     0,     0,    92,   183,
     184,   185,   186,   187,   188,     0,     0,     0,     0,     0,
       0,     0,   281,   282,   192,   193,   183,   184,   185,   186,
     187,   188,   184,   185,   186,   187,   188,     0,     0,     0,
       0,   192,   193,     0,     0,     0,   192,   193,   153,   154,
     155,   156,   157,     0,   158,   159,     0,     0,   160,   161,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     162,   163,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   164,   165,   166,   167,   168,   169,   170,   171,
     172
};

static const yytype_int16 yycheck[] =
{
       2,     8,   197,     0,    42,    43,    97,    45,    46,     2,
       0,     2,    37,    37,    95,    37,   232,    94,   151,    37,
      43,   121,   122,   203,   121,    37,   121,   122,     0,   121,
      60,   131,    37,   136,   131,    60,   131,    60,    60,   131,
      42,    43,    60,    45,    46,   261,   137,   138,    60,   265,
      37,   132,    57,    58,    59,    37,    37,    95,    37,    97,
     137,   138,   128,   129,    91,     5,   109,     7,   111,     9,
      10,   121,   122,   139,   140,   109,    37,   111,    37,    60,
      61,    62,    63,    64,    60,   218,    60,   125,    37,   284,
     139,   140,    94,    95,   132,    97,    57,    58,    59,   137,
     138,    94,    95,    94,    95,   132,   286,   109,   132,   111,
     124,   125,   150,   151,    65,    66,    37,   121,   122,   133,
     134,   135,   129,   125,   121,   122,   129,   132,   133,   134,
     135,   121,   122,   131,   131,   137,   138,   218,    60,   136,
     217,   131,   123,   131,   137,   138,   137,   138,   150,   151,
     177,   132,   121,   122,   181,   182,   183,   184,   185,   186,
     187,   188,    37,    37,    37,   192,   193,   194,   195,    37,
      37,   132,   133,   134,   135,   126,   127,   128,   129,   217,
     218,    37,    37,   274,   275,    62,    37,    37,   139,   140,
     126,   127,   128,   129,   131,     4,     4,     3,     3,    48,
      37,     2,   137,   139,   140,   173,   232,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   217,   218,    -1,    -1,    -1,
      -1,    -1,    -1,     0,   217,   218,   217,   218,    -1,    -1,
      -1,    -1,    -1,    -1,    11,    12,   274,   275,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    -1,    -1,
      37,    38,    39,    40,    41,    42,    43,    44,    45,    46,
      -1,    -1,   274,   275,    -1,    -1,    -1,    -1,    -1,    56,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      67,    68,    69,    70,    71,    72,    73,    74,    75,    76,
      77,    78,    79,    80,    81,    82,    83,    84,    85,    86,
      87,    88,    89,    90,    91,    92,    93,    94,    95,    96,
      97,    98,    99,   100,   101,   102,   103,   104,   105,   106,
     107,   108,   109,   110,   111,   112,   113,   114,   115,   116,
     117,   118,   119,    -1,    -1,    -1,   123,    -1,    -1,    -1,
     127,    -1,    11,    12,    -1,   132,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    -1,    -1,    37,    38,
      39,    40,    41,    42,    43,    44,    45,    46,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    56,    -1,    -1,
      -1,    60,    61,    62,    63,    64,    -1,    -1,    67,    68,
      69,    70,    71,    72,    73,    74,    75,    76,    77,    78,
      79,    80,    81,    82,    83,    84,    85,    86,    87,    88,
      89,    90,    91,    92,    93,    94,    95,    96,    97,    98,
      99,   100,   101,   102,   103,   104,   105,   106,   107,   108,
     109,   110,   111,   112,   113,   114,   115,   116,   117,   118,
     119,    -1,    -1,    -1,   123,    -1,    -1,    -1,   127,    -1,
      11,    12,    -1,   132,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    -1,    -1,    37,    38,    39,    40,
      41,    42,    43,    44,    45,    46,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    56,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    67,    68,    69,    70,
      71,    72,    73,    74,    75,    76,    77,    78,    79,    80,
      81,    82,    83,    84,    85,    86,    87,    88,    89,    90,
      91,    92,    93,    94,    95,    96,    97,    98,    99,   100,
     101,   102,   103,   104,   105,   106,   107,   108,   109,   110,
     111,   112,   113,   114,   115,   116,   117,   118,   119,    -1,
      -1,    -1,   123,    -1,    -1,    -1,   127,    -1,    -1,    -1,
      -1,   132,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    -1,    -1,    37,    -1,    57,    58,    59,    -1,    -1,
      -1,    -1,    -1,    65,    66,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    56,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    67,    68,    69,    70,    71,    -1,    -1,
      65,    66,    -1,    77,    78,    79,    80,    81,    82,    83,
      84,    85,    86,    87,    88,    89,    90,    65,    66,    -1,
      -1,    -1,    65,    66,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   105,   124,   125,   126,   127,   128,   129,    -1,    -1,
      -1,   133,   134,   135,    -1,    -1,    -1,   139,   140,    -1,
      -1,    -1,    -1,   127,    -1,    -1,    -1,    -1,   132,   124,
     125,   126,   127,   128,   129,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   137,   138,   139,   140,   124,   125,   126,   127,
     128,   129,   125,   126,   127,   128,   129,    -1,    -1,    -1,
      -1,   139,   140,    -1,    -1,    -1,   139,   140,     3,     4,
       5,     6,     7,    -1,     9,    10,    -1,    -1,    13,    14,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      35,    36,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    47,    48,    49,    50,    51,    52,    53,    54,
      55
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,   142,   143,     0,    11,    12,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    37,    38,    39,    40,
      41,    42,    43,    44,    45,    46,    56,    67,    68,    69,
      70,    71,    72,    73,    74,    75,    76,    77,    78,    79,
      80,    81,    82,    83,    84,    85,    86,    87,    88,    89,
      90,    91,    92,    93,    94,    95,    96,    97,    98,    99,
     100,   101,   102,   103,   104,   105,   106,   107,   108,   109,
     110,   111,   112,   113,   114,   115,   116,   117,   118,   119,
     123,   127,   132,   144,   149,   150,   153,   154,   155,   156,
     160,   161,   162,   167,   173,   174,   176,   177,   178,   179,
     183,   184,    37,    37,    37,    37,    60,    60,    37,    37,
      37,    60,   169,    60,   170,   150,   176,   176,   176,   176,
      43,    60,   150,   160,   173,   121,   122,   145,   146,   153,
     144,   174,   176,    60,    61,    62,    63,    64,   147,   148,
     149,   150,   176,     3,     4,     5,     6,     7,     9,    10,
      13,    14,    35,    36,    47,    48,    49,    50,    51,    52,
      53,    54,    55,   157,   158,   159,   163,   136,    57,    58,
      59,    65,    66,   124,   125,   126,   127,   128,   129,   133,
     134,   135,   139,   140,   171,   172,    37,   150,   171,   172,
     180,   181,    37,   150,   171,   172,   185,   186,   124,   125,
     133,   134,   135,   175,   176,   173,   147,   149,   150,   153,
     176,   147,   153,   131,   131,   131,     8,   129,   129,   147,
     148,   151,   152,   176,   121,   122,   121,   122,    37,    60,
     164,    60,   166,    37,    60,   168,   158,   173,   173,   173,
     173,   173,   173,   173,   173,   173,   173,   173,   173,   173,
     181,   182,    37,    37,   186,   187,    37,    37,    37,   176,
      62,    37,    37,   131,   145,   146,     4,     4,     3,     3,
      48,   137,   138,   131,   146,   131,   146,   147,   147,    37,
      60,   165,    37,   181,   186,   137
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,   141,   142,   142,   143,   144,   144,   144,   144,   144,
     145,   146,   147,   147,   147,   148,   148,   148,   148,   148,
     148,   148,   148,   148,   149,   150,   151,   151,   151,   152,
     152,   153,   153,   154,   154,   154,   154,   154,   154,   155,
     155,   155,   155,   155,   155,   155,   155,   155,   155,   155,
     156,   156,   157,   157,   157,   157,   157,   157,   157,   157,
     157,   157,   157,   157,   158,   158,   158,   158,   159,   160,
     160,   160,   160,   160,   160,   160,   160,   160,   160,   160,
     160,   160,   160,   160,   160,   160,   160,   160,   160,   160,
     160,   160,   160,   160,   160,   160,   160,   160,   160,   160,
     160,   160,   160,   160,   160,   160,   160,   160,   161,   161,
     161,   161,   161,   161,   161,   161,   161,   161,   161,   161,
     161,   161,   161,   161,   161,   161,   161,   161,   162,   162,
     162,   162,   162,   162,   163,   163,   163,   163,   164,   164,
     165,   165,   166,   167,   167,   167,   168,   168,   169,   169,
     170,   171,   171,   171,   172,   172,   172,   173,   173,   174,
     174,   174,   174,   174,   174,   174,   174,   174,   174,   174,
     174,   174,   174,   174,   175,   175,   175,   175,   175,   176,
     176,   177,   177,   177,   177,   177,   177,   177,   178,   178,
     178,   178,   179,   179,   180,   180,   180,   180,   181,   182,
     182,   183,   183,   183,   183,   183,   183,   184,   184,   184,
     184,   184,   184,   184,   184,   185,   185,   185,   185,   186,
     187,   187
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
       2,     2,     4,     1,     1,     2,     2,     1,     2,     1,
       1,     2,     1,     2,     1,     1,     2,     1,     2,     2,
       2,     2,     2,     2,     4,     2,     2,     2,     1,     1,
       1,     1,     1,     1,     2,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     4,
       6,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     2,     3,     1,     1,     1,     1,     1,     1,     1,
       3,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     2,     3,     1,     1,
       3,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     2,     2,     3,     1,
       1,     3
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
      yyerror (yyscanner, cstate, YY_("syntax error: cannot back up")); \
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
                  Type, Value, yyscanner, cstate); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *yyscanner, compiler_state_t *cstate)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  YYUSE (yyscanner);
  YYUSE (cstate);
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
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *yyscanner, compiler_state_t *cstate)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, yyscanner, cstate);
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
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule, void *yyscanner, compiler_state_t *cstate)
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
                                              , yyscanner, cstate);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, yyscanner, cstate); \
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
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, void *yyscanner, compiler_state_t *cstate)
{
  YYUSE (yyvaluep);
  YYUSE (yyscanner);
  YYUSE (cstate);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void *yyscanner, compiler_state_t *cstate)
{
/* The lookahead symbol.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs;

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
      yychar = yylex (&yylval, yyscanner);
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
#line 432 "grammar.y" /* yacc.c:1646  */
    {
	/*
	 * I'm not sure we have a reason to use yynerrs, but it's
	 * declared, and incremented, whether we need it or not,
	 * which means that Clang 15 will give a "used but not
	 * set" warning.  This should suppress the warning for
	 * yynerrs without suppressing it for other variables.
	 */
	(void) yynerrs;
	CHECK_INT_VAL(finish_parse(cstate, (yyvsp[0].blk).b));
}
#line 2029 "grammar.c" /* yacc.c:1646  */
    break;

  case 4:
#line 445 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).q = qerr; }
#line 2035 "grammar.c" /* yacc.c:1646  */
    break;

  case 6:
#line 448 "grammar.y" /* yacc.c:1646  */
    { gen_and((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2041 "grammar.c" /* yacc.c:1646  */
    break;

  case 7:
#line 449 "grammar.y" /* yacc.c:1646  */
    { gen_and((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2047 "grammar.c" /* yacc.c:1646  */
    break;

  case 8:
#line 450 "grammar.y" /* yacc.c:1646  */
    { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2053 "grammar.c" /* yacc.c:1646  */
    break;

  case 9:
#line 451 "grammar.y" /* yacc.c:1646  */
    { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2059 "grammar.c" /* yacc.c:1646  */
    break;

  case 10:
#line 453 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk) = (yyvsp[-1].blk); }
#line 2065 "grammar.c" /* yacc.c:1646  */
    break;

  case 11:
#line 455 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk) = (yyvsp[-1].blk); }
#line 2071 "grammar.c" /* yacc.c:1646  */
    break;

  case 13:
#line 458 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.blk).b = gen_ncode(cstate, NULL, (yyvsp[0].h),
						   (yyval.blk).q = (yyvsp[-1].blk).q))); }
#line 2078 "grammar.c" /* yacc.c:1646  */
    break;

  case 14:
#line 460 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk) = (yyvsp[-1].blk); }
#line 2084 "grammar.c" /* yacc.c:1646  */
    break;

  case 15:
#line 462 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL((yyvsp[0].s)); CHECK_PTR_VAL(((yyval.blk).b = gen_scode(cstate, (yyvsp[0].s), (yyval.blk).q = (yyvsp[-1].blk).q))); }
#line 2090 "grammar.c" /* yacc.c:1646  */
    break;

  case 16:
#line 463 "grammar.y" /* yacc.c:1646  */
    {
				  CHECK_PTR_VAL((yyvsp[-2].s));
				  /* Check whether HID/NUM is being used when appropriate */
				  (yyval.blk).q = (yyvsp[-3].blk).q;
				  if ((yyval.blk).q.addr == Q_PORT) {
					bpf_set_error(cstate, "'port' modifier applied to IP address and prefix length");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PORTRANGE) {
					bpf_set_error(cstate, "'portrange' modifier applied to IP address and prefix length");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PROTO) {
					bpf_set_error(cstate, "'proto' modifier applied to IP address and prefix length");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PROTOCHAIN) {
					bpf_set_error(cstate, "'protochain' modifier applied to IP address and prefix length");
					YYABORT;
				  }
				  CHECK_PTR_VAL(((yyval.blk).b = gen_mcode(cstate, (yyvsp[-2].s), NULL, (yyvsp[0].h), (yyval.blk).q)));
				}
#line 2114 "grammar.c" /* yacc.c:1646  */
    break;

  case 17:
#line 482 "grammar.y" /* yacc.c:1646  */
    {
				  CHECK_PTR_VAL((yyvsp[-2].s));
				  /* Check whether HID mask HID is being used when appropriate */
				  (yyval.blk).q = (yyvsp[-3].blk).q;
				  if ((yyval.blk).q.addr == Q_PORT) {
					bpf_set_error(cstate, "'port' modifier applied to IP address and netmask");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PORTRANGE) {
					bpf_set_error(cstate, "'portrange' modifier applied to IP address and netmask");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PROTO) {
					bpf_set_error(cstate, "'proto' modifier applied to IP address and netmask");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PROTOCHAIN) {
					bpf_set_error(cstate, "'protochain' modifier applied to IP address and netmask");
					YYABORT;
				  }
				  CHECK_PTR_VAL(((yyval.blk).b = gen_mcode(cstate, (yyvsp[-2].s), (yyvsp[0].s), 0, (yyval.blk).q)));
				}
#line 2138 "grammar.c" /* yacc.c:1646  */
    break;

  case 18:
#line 501 "grammar.y" /* yacc.c:1646  */
    {
				  CHECK_PTR_VAL((yyvsp[0].s));
				  /* Check whether HID is being used when appropriate */
				  (yyval.blk).q = (yyvsp[-1].blk).q;
				  if ((yyval.blk).q.addr == Q_PORT) {
					bpf_set_error(cstate, "'port' modifier applied to IP address");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PORTRANGE) {
					bpf_set_error(cstate, "'portrange' modifier applied to IP address");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PROTO) {
					bpf_set_error(cstate, "'proto' modifier applied to IP address");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PROTOCHAIN) {
					bpf_set_error(cstate, "'protochain' modifier applied to IP address");
					YYABORT;
				  }
				  CHECK_PTR_VAL(((yyval.blk).b = gen_ncode(cstate, (yyvsp[0].s), 0, (yyval.blk).q)));
				}
#line 2162 "grammar.c" /* yacc.c:1646  */
    break;

  case 19:
#line 520 "grammar.y" /* yacc.c:1646  */
    {
				  CHECK_PTR_VAL((yyvsp[-2].s));
#ifdef INET6
				  /* Check whether HID6/NUM is being used when appropriate */
				  (yyval.blk).q = (yyvsp[-3].blk).q;
				  if ((yyval.blk).q.addr == Q_PORT) {
					bpf_set_error(cstate, "'port' modifier applied to IP address and prefix length");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PORTRANGE) {
					bpf_set_error(cstate, "'portrange' modifier applied to IP address and prefix length");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PROTO) {
					bpf_set_error(cstate, "'proto' modifier applied to IP address and prefix length ");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PROTOCHAIN) {
					bpf_set_error(cstate, "'protochain' modifier applied to IP address and prefix length");
					YYABORT;
				  }
				  CHECK_PTR_VAL(((yyval.blk).b = gen_mcode6(cstate, (yyvsp[-2].s), (yyvsp[0].h), (yyval.blk).q)));
#else
				  bpf_set_error(cstate, "IPv6 addresses not supported "
					"in this configuration");
				  YYABORT;
#endif /*INET6*/
				}
#line 2192 "grammar.c" /* yacc.c:1646  */
    break;

  case 20:
#line 545 "grammar.y" /* yacc.c:1646  */
    {
				  CHECK_PTR_VAL((yyvsp[0].s));
#ifdef INET6
				  /* Check whether HID6 is being used when appropriate */
				  (yyval.blk).q = (yyvsp[-1].blk).q;
				  if ((yyval.blk).q.addr == Q_PORT) {
					bpf_set_error(cstate, "'port' modifier applied to IP address");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PORTRANGE) {
					bpf_set_error(cstate, "'portrange' modifier applied to IP address");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PROTO) {
					bpf_set_error(cstate, "'proto' modifier applied to 'ip6addr/prefixlen");
					YYABORT;
				  } else if ((yyval.blk).q.addr == Q_PROTOCHAIN) {
					bpf_set_error(cstate, "'protochain' modifier applied to IP address");
					YYABORT;
				  }
				  CHECK_PTR_VAL(((yyval.blk).b = gen_mcode6(cstate, (yyvsp[0].s), 128, (yyval.blk).q)));
#else
				  bpf_set_error(cstate, "IPv6 addresses not supported "
					"in this configuration");
				  YYABORT;
#endif /*INET6*/
				}
#line 2222 "grammar.c" /* yacc.c:1646  */
    break;

  case 21:
#line 570 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL((yyvsp[0].s)); CHECK_PTR_VAL(((yyval.blk).b = gen_ecode(cstate, (yyvsp[0].s), (yyval.blk).q = (yyvsp[-1].blk).q))); }
#line 2228 "grammar.c" /* yacc.c:1646  */
    break;

  case 22:
#line 571 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL((yyvsp[0].s)); CHECK_PTR_VAL(((yyval.blk).b = gen_acode(cstate, (yyvsp[0].s), (yyval.blk).q = (yyvsp[-1].blk).q))); }
#line 2234 "grammar.c" /* yacc.c:1646  */
    break;

  case 23:
#line 572 "grammar.y" /* yacc.c:1646  */
    { gen_not((yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2240 "grammar.c" /* yacc.c:1646  */
    break;

  case 24:
#line 574 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk) = (yyvsp[-1].blk); }
#line 2246 "grammar.c" /* yacc.c:1646  */
    break;

  case 25:
#line 576 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk) = (yyvsp[-1].blk); }
#line 2252 "grammar.c" /* yacc.c:1646  */
    break;

  case 27:
#line 579 "grammar.y" /* yacc.c:1646  */
    { gen_and((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2258 "grammar.c" /* yacc.c:1646  */
    break;

  case 28:
#line 580 "grammar.y" /* yacc.c:1646  */
    { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2264 "grammar.c" /* yacc.c:1646  */
    break;

  case 29:
#line 582 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.blk).b = gen_ncode(cstate, NULL, (yyvsp[0].h),
						   (yyval.blk).q = (yyvsp[-1].blk).q))); }
#line 2271 "grammar.c" /* yacc.c:1646  */
    break;

  case 32:
#line 587 "grammar.y" /* yacc.c:1646  */
    { gen_not((yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 2277 "grammar.c" /* yacc.c:1646  */
    break;

  case 33:
#line 589 "grammar.y" /* yacc.c:1646  */
    { QSET((yyval.blk).q, (yyvsp[-2].i), (yyvsp[-1].i), (yyvsp[0].i)); }
#line 2283 "grammar.c" /* yacc.c:1646  */
    break;

  case 34:
#line 590 "grammar.y" /* yacc.c:1646  */
    { QSET((yyval.blk).q, (yyvsp[-1].i), (yyvsp[0].i), Q_DEFAULT); }
#line 2289 "grammar.c" /* yacc.c:1646  */
    break;

  case 35:
#line 591 "grammar.y" /* yacc.c:1646  */
    { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, (yyvsp[0].i)); }
#line 2295 "grammar.c" /* yacc.c:1646  */
    break;

  case 36:
#line 592 "grammar.y" /* yacc.c:1646  */
    { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, Q_PROTO); }
#line 2301 "grammar.c" /* yacc.c:1646  */
    break;

  case 37:
#line 593 "grammar.y" /* yacc.c:1646  */
    {
#ifdef NO_PROTOCHAIN
				  bpf_set_error(cstate, "protochain not supported");
				  YYABORT;
#else
				  QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, Q_PROTOCHAIN);
#endif
				}
#line 2314 "grammar.c" /* yacc.c:1646  */
    break;

  case 38:
#line 601 "grammar.y" /* yacc.c:1646  */
    { QSET((yyval.blk).q, (yyvsp[-1].i), Q_DEFAULT, (yyvsp[0].i)); }
#line 2320 "grammar.c" /* yacc.c:1646  */
    break;

  case 39:
#line 603 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk) = (yyvsp[0].blk); }
#line 2326 "grammar.c" /* yacc.c:1646  */
    break;

  case 40:
#line 604 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = (yyvsp[-1].blk).b; (yyval.blk).q = (yyvsp[-2].blk).q; }
#line 2332 "grammar.c" /* yacc.c:1646  */
    break;

  case 41:
#line 605 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.blk).b = gen_proto_abbrev(cstate, (yyvsp[0].i)))); (yyval.blk).q = qerr; }
#line 2338 "grammar.c" /* yacc.c:1646  */
    break;

  case 42:
#line 606 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.blk).b = gen_relation(cstate, (yyvsp[-1].i), (yyvsp[-2].a), (yyvsp[0].a), 0)));
				  (yyval.blk).q = qerr; }
#line 2345 "grammar.c" /* yacc.c:1646  */
    break;

  case 43:
#line 608 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.blk).b = gen_relation(cstate, (yyvsp[-1].i), (yyvsp[-2].a), (yyvsp[0].a), 1)));
				  (yyval.blk).q = qerr; }
#line 2352 "grammar.c" /* yacc.c:1646  */
    break;

  case 44:
#line 610 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = (yyvsp[0].rblk); (yyval.blk).q = qerr; }
#line 2358 "grammar.c" /* yacc.c:1646  */
    break;

  case 45:
#line 611 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.blk).b = gen_atmtype_abbrev(cstate, (yyvsp[0].i)))); (yyval.blk).q = qerr; }
#line 2364 "grammar.c" /* yacc.c:1646  */
    break;

  case 46:
#line 612 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.blk).b = gen_atmmulti_abbrev(cstate, (yyvsp[0].i)))); (yyval.blk).q = qerr; }
#line 2370 "grammar.c" /* yacc.c:1646  */
    break;

  case 47:
#line 613 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = (yyvsp[0].blk).b; (yyval.blk).q = qerr; }
#line 2376 "grammar.c" /* yacc.c:1646  */
    break;

  case 48:
#line 614 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.blk).b = gen_mtp2type_abbrev(cstate, (yyvsp[0].i)))); (yyval.blk).q = qerr; }
#line 2382 "grammar.c" /* yacc.c:1646  */
    break;

  case 49:
#line 615 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = (yyvsp[0].blk).b; (yyval.blk).q = qerr; }
#line 2388 "grammar.c" /* yacc.c:1646  */
    break;

  case 51:
#line 619 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_DEFAULT; }
#line 2394 "grammar.c" /* yacc.c:1646  */
    break;

  case 52:
#line 622 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_SRC; }
#line 2400 "grammar.c" /* yacc.c:1646  */
    break;

  case 53:
#line 623 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_DST; }
#line 2406 "grammar.c" /* yacc.c:1646  */
    break;

  case 54:
#line 624 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_OR; }
#line 2412 "grammar.c" /* yacc.c:1646  */
    break;

  case 55:
#line 625 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_OR; }
#line 2418 "grammar.c" /* yacc.c:1646  */
    break;

  case 56:
#line 626 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_AND; }
#line 2424 "grammar.c" /* yacc.c:1646  */
    break;

  case 57:
#line 627 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_AND; }
#line 2430 "grammar.c" /* yacc.c:1646  */
    break;

  case 58:
#line 628 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ADDR1; }
#line 2436 "grammar.c" /* yacc.c:1646  */
    break;

  case 59:
#line 629 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ADDR2; }
#line 2442 "grammar.c" /* yacc.c:1646  */
    break;

  case 60:
#line 630 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ADDR3; }
#line 2448 "grammar.c" /* yacc.c:1646  */
    break;

  case 61:
#line 631 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ADDR4; }
#line 2454 "grammar.c" /* yacc.c:1646  */
    break;

  case 62:
#line 632 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_RA; }
#line 2460 "grammar.c" /* yacc.c:1646  */
    break;

  case 63:
#line 633 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_TA; }
#line 2466 "grammar.c" /* yacc.c:1646  */
    break;

  case 64:
#line 636 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_HOST; }
#line 2472 "grammar.c" /* yacc.c:1646  */
    break;

  case 65:
#line 637 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_NET; }
#line 2478 "grammar.c" /* yacc.c:1646  */
    break;

  case 66:
#line 638 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_PORT; }
#line 2484 "grammar.c" /* yacc.c:1646  */
    break;

  case 67:
#line 639 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_PORTRANGE; }
#line 2490 "grammar.c" /* yacc.c:1646  */
    break;

  case 68:
#line 642 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_GATEWAY; }
#line 2496 "grammar.c" /* yacc.c:1646  */
    break;

  case 69:
#line 644 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_LINK; }
#line 2502 "grammar.c" /* yacc.c:1646  */
    break;

  case 70:
#line 645 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_IP; }
#line 2508 "grammar.c" /* yacc.c:1646  */
    break;

  case 71:
#line 646 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ARP; }
#line 2514 "grammar.c" /* yacc.c:1646  */
    break;

  case 72:
#line 647 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_RARP; }
#line 2520 "grammar.c" /* yacc.c:1646  */
    break;

  case 73:
#line 648 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_SCTP; }
#line 2526 "grammar.c" /* yacc.c:1646  */
    break;

  case 74:
#line 649 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_TCP; }
#line 2532 "grammar.c" /* yacc.c:1646  */
    break;

  case 75:
#line 650 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_UDP; }
#line 2538 "grammar.c" /* yacc.c:1646  */
    break;

  case 76:
#line 651 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ICMP; }
#line 2544 "grammar.c" /* yacc.c:1646  */
    break;

  case 77:
#line 652 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_IGMP; }
#line 2550 "grammar.c" /* yacc.c:1646  */
    break;

  case 78:
#line 653 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_IGRP; }
#line 2556 "grammar.c" /* yacc.c:1646  */
    break;

  case 79:
#line 654 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_PIM; }
#line 2562 "grammar.c" /* yacc.c:1646  */
    break;

  case 80:
#line 655 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_VRRP; }
#line 2568 "grammar.c" /* yacc.c:1646  */
    break;

  case 81:
#line 656 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_CARP; }
#line 2574 "grammar.c" /* yacc.c:1646  */
    break;

  case 82:
#line 657 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ATALK; }
#line 2580 "grammar.c" /* yacc.c:1646  */
    break;

  case 83:
#line 658 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_AARP; }
#line 2586 "grammar.c" /* yacc.c:1646  */
    break;

  case 84:
#line 659 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_DECNET; }
#line 2592 "grammar.c" /* yacc.c:1646  */
    break;

  case 85:
#line 660 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_LAT; }
#line 2598 "grammar.c" /* yacc.c:1646  */
    break;

  case 86:
#line 661 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_SCA; }
#line 2604 "grammar.c" /* yacc.c:1646  */
    break;

  case 87:
#line 662 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_MOPDL; }
#line 2610 "grammar.c" /* yacc.c:1646  */
    break;

  case 88:
#line 663 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_MOPRC; }
#line 2616 "grammar.c" /* yacc.c:1646  */
    break;

  case 89:
#line 664 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_IPV6; }
#line 2622 "grammar.c" /* yacc.c:1646  */
    break;

  case 90:
#line 665 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ICMPV6; }
#line 2628 "grammar.c" /* yacc.c:1646  */
    break;

  case 91:
#line 666 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_AH; }
#line 2634 "grammar.c" /* yacc.c:1646  */
    break;

  case 92:
#line 667 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ESP; }
#line 2640 "grammar.c" /* yacc.c:1646  */
    break;

  case 93:
#line 668 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISO; }
#line 2646 "grammar.c" /* yacc.c:1646  */
    break;

  case 94:
#line 669 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ESIS; }
#line 2652 "grammar.c" /* yacc.c:1646  */
    break;

  case 95:
#line 670 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS; }
#line 2658 "grammar.c" /* yacc.c:1646  */
    break;

  case 96:
#line 671 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_L1; }
#line 2664 "grammar.c" /* yacc.c:1646  */
    break;

  case 97:
#line 672 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_L2; }
#line 2670 "grammar.c" /* yacc.c:1646  */
    break;

  case 98:
#line 673 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_IIH; }
#line 2676 "grammar.c" /* yacc.c:1646  */
    break;

  case 99:
#line 674 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_LSP; }
#line 2682 "grammar.c" /* yacc.c:1646  */
    break;

  case 100:
#line 675 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_SNP; }
#line 2688 "grammar.c" /* yacc.c:1646  */
    break;

  case 101:
#line 676 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_PSNP; }
#line 2694 "grammar.c" /* yacc.c:1646  */
    break;

  case 102:
#line 677 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_ISIS_CSNP; }
#line 2700 "grammar.c" /* yacc.c:1646  */
    break;

  case 103:
#line 678 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_CLNP; }
#line 2706 "grammar.c" /* yacc.c:1646  */
    break;

  case 104:
#line 679 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_STP; }
#line 2712 "grammar.c" /* yacc.c:1646  */
    break;

  case 105:
#line 680 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_IPX; }
#line 2718 "grammar.c" /* yacc.c:1646  */
    break;

  case 106:
#line 681 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_NETBEUI; }
#line 2724 "grammar.c" /* yacc.c:1646  */
    break;

  case 107:
#line 682 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = Q_RADIO; }
#line 2730 "grammar.c" /* yacc.c:1646  */
    break;

  case 108:
#line 684 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_broadcast(cstate, (yyvsp[-1].i)))); }
#line 2736 "grammar.c" /* yacc.c:1646  */
    break;

  case 109:
#line 685 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_multicast(cstate, (yyvsp[-1].i)))); }
#line 2742 "grammar.c" /* yacc.c:1646  */
    break;

  case 110:
#line 686 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_less(cstate, (yyvsp[0].h)))); }
#line 2748 "grammar.c" /* yacc.c:1646  */
    break;

  case 111:
#line 687 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_greater(cstate, (yyvsp[0].h)))); }
#line 2754 "grammar.c" /* yacc.c:1646  */
    break;

  case 112:
#line 688 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_byteop(cstate, (yyvsp[-1].i), (yyvsp[-2].h), (yyvsp[0].h)))); }
#line 2760 "grammar.c" /* yacc.c:1646  */
    break;

  case 113:
#line 689 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_inbound(cstate, 0))); }
#line 2766 "grammar.c" /* yacc.c:1646  */
    break;

  case 114:
#line 690 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_inbound(cstate, 1))); }
#line 2772 "grammar.c" /* yacc.c:1646  */
    break;

  case 115:
#line 691 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_ifindex(cstate, (yyvsp[0].h)))); }
#line 2778 "grammar.c" /* yacc.c:1646  */
    break;

  case 116:
#line 692 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_vlan(cstate, (yyvsp[0].h), 1))); }
#line 2784 "grammar.c" /* yacc.c:1646  */
    break;

  case 117:
#line 693 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_vlan(cstate, 0, 0))); }
#line 2790 "grammar.c" /* yacc.c:1646  */
    break;

  case 118:
#line 694 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_mpls(cstate, (yyvsp[0].h), 1))); }
#line 2796 "grammar.c" /* yacc.c:1646  */
    break;

  case 119:
#line 695 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_mpls(cstate, 0, 0))); }
#line 2802 "grammar.c" /* yacc.c:1646  */
    break;

  case 120:
#line 696 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_pppoed(cstate))); }
#line 2808 "grammar.c" /* yacc.c:1646  */
    break;

  case 121:
#line 697 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_pppoes(cstate, (yyvsp[0].h), 1))); }
#line 2814 "grammar.c" /* yacc.c:1646  */
    break;

  case 122:
#line 698 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_pppoes(cstate, 0, 0))); }
#line 2820 "grammar.c" /* yacc.c:1646  */
    break;

  case 123:
#line 699 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_geneve(cstate, (yyvsp[0].h), 1))); }
#line 2826 "grammar.c" /* yacc.c:1646  */
    break;

  case 124:
#line 700 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_geneve(cstate, 0, 0))); }
#line 2832 "grammar.c" /* yacc.c:1646  */
    break;

  case 125:
#line 701 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = (yyvsp[0].rblk); }
#line 2838 "grammar.c" /* yacc.c:1646  */
    break;

  case 126:
#line 702 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = (yyvsp[0].rblk); }
#line 2844 "grammar.c" /* yacc.c:1646  */
    break;

  case 127:
#line 703 "grammar.y" /* yacc.c:1646  */
    { (yyval.rblk) = (yyvsp[0].rblk); }
#line 2850 "grammar.c" /* yacc.c:1646  */
    break;

  case 128:
#line 706 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL((yyvsp[0].s)); CHECK_PTR_VAL(((yyval.rblk) = gen_pf_ifname(cstate, (yyvsp[0].s)))); }
#line 2856 "grammar.c" /* yacc.c:1646  */
    break;

  case 129:
#line 707 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL((yyvsp[0].s)); CHECK_PTR_VAL(((yyval.rblk) = gen_pf_ruleset(cstate, (yyvsp[0].s)))); }
#line 2862 "grammar.c" /* yacc.c:1646  */
    break;

  case 130:
#line 708 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_pf_rnr(cstate, (yyvsp[0].h)))); }
#line 2868 "grammar.c" /* yacc.c:1646  */
    break;

  case 131:
#line 709 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_pf_srnr(cstate, (yyvsp[0].h)))); }
#line 2874 "grammar.c" /* yacc.c:1646  */
    break;

  case 132:
#line 710 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_pf_reason(cstate, (yyvsp[0].i)))); }
#line 2880 "grammar.c" /* yacc.c:1646  */
    break;

  case 133:
#line 711 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_pf_action(cstate, (yyvsp[0].i)))); }
#line 2886 "grammar.c" /* yacc.c:1646  */
    break;

  case 134:
#line 715 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_p80211_type(cstate, (yyvsp[-2].i) | (yyvsp[0].i),
					IEEE80211_FC0_TYPE_MASK |
					IEEE80211_FC0_SUBTYPE_MASK)));
				}
#line 2895 "grammar.c" /* yacc.c:1646  */
    break;

  case 135:
#line 719 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_p80211_type(cstate, (yyvsp[0].i),
					IEEE80211_FC0_TYPE_MASK)));
				}
#line 2903 "grammar.c" /* yacc.c:1646  */
    break;

  case 136:
#line 722 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_p80211_type(cstate, (yyvsp[0].i),
					IEEE80211_FC0_TYPE_MASK |
					IEEE80211_FC0_SUBTYPE_MASK)));
				}
#line 2912 "grammar.c" /* yacc.c:1646  */
    break;

  case 137:
#line 726 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_p80211_fcdir(cstate, (yyvsp[0].i)))); }
#line 2918 "grammar.c" /* yacc.c:1646  */
    break;

  case 138:
#line 729 "grammar.y" /* yacc.c:1646  */
    { if (((yyvsp[0].h) & (~IEEE80211_FC0_TYPE_MASK)) != 0) {
					bpf_set_error(cstate, "invalid 802.11 type value 0x%02x", (yyvsp[0].h));
					YYABORT;
				  }
				  (yyval.i) = (int)(yyvsp[0].h);
				}
#line 2929 "grammar.c" /* yacc.c:1646  */
    break;

  case 139:
#line 735 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL((yyvsp[0].s));
				  (yyval.i) = str2tok((yyvsp[0].s), ieee80211_types);
				  if ((yyval.i) == -1) {
					bpf_set_error(cstate, "unknown 802.11 type name \"%s\"", (yyvsp[0].s));
					YYABORT;
				  }
				}
#line 2941 "grammar.c" /* yacc.c:1646  */
    break;

  case 140:
#line 744 "grammar.y" /* yacc.c:1646  */
    { if (((yyvsp[0].h) & (~IEEE80211_FC0_SUBTYPE_MASK)) != 0) {
					bpf_set_error(cstate, "invalid 802.11 subtype value 0x%02x", (yyvsp[0].h));
					YYABORT;
				  }
				  (yyval.i) = (int)(yyvsp[0].h);
				}
#line 2952 "grammar.c" /* yacc.c:1646  */
    break;

  case 141:
#line 750 "grammar.y" /* yacc.c:1646  */
    { const struct tok *types = NULL;
				  int i;
				  CHECK_PTR_VAL((yyvsp[0].s));
				  for (i = 0;; i++) {
					if (ieee80211_type_subtypes[i].tok == NULL) {
						/* Ran out of types */
						bpf_set_error(cstate, "unknown 802.11 type");
						YYABORT;
					}
					if ((yyvsp[(-1) - (1)].i) == ieee80211_type_subtypes[i].type) {
						types = ieee80211_type_subtypes[i].tok;
						break;
					}
				  }

				  (yyval.i) = str2tok((yyvsp[0].s), types);
				  if ((yyval.i) == -1) {
					bpf_set_error(cstate, "unknown 802.11 subtype name \"%s\"", (yyvsp[0].s));
					YYABORT;
				  }
				}
#line 2978 "grammar.c" /* yacc.c:1646  */
    break;

  case 142:
#line 773 "grammar.y" /* yacc.c:1646  */
    { int i;
				  CHECK_PTR_VAL((yyvsp[0].s));
				  for (i = 0;; i++) {
					if (ieee80211_type_subtypes[i].tok == NULL) {
						/* Ran out of types */
						bpf_set_error(cstate, "unknown 802.11 type name");
						YYABORT;
					}
					(yyval.i) = str2tok((yyvsp[0].s), ieee80211_type_subtypes[i].tok);
					if ((yyval.i) != -1) {
						(yyval.i) |= ieee80211_type_subtypes[i].type;
						break;
					}
				  }
				}
#line 2998 "grammar.c" /* yacc.c:1646  */
    break;

  case 143:
#line 790 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_llc(cstate))); }
#line 3004 "grammar.c" /* yacc.c:1646  */
    break;

  case 144:
#line 791 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL((yyvsp[0].s));
				  if (pcapint_strcasecmp((yyvsp[0].s), "i") == 0) {
					CHECK_PTR_VAL(((yyval.rblk) = gen_llc_i(cstate)));
				  } else if (pcapint_strcasecmp((yyvsp[0].s), "s") == 0) {
					CHECK_PTR_VAL(((yyval.rblk) = gen_llc_s(cstate)));
				  } else if (pcapint_strcasecmp((yyvsp[0].s), "u") == 0) {
					CHECK_PTR_VAL(((yyval.rblk) = gen_llc_u(cstate)));
				  } else {
					int subtype;

					subtype = str2tok((yyvsp[0].s), llc_s_subtypes);
					if (subtype != -1) {
						CHECK_PTR_VAL(((yyval.rblk) = gen_llc_s_subtype(cstate, subtype)));
					} else {
						subtype = str2tok((yyvsp[0].s), llc_u_subtypes);
						if (subtype == -1) {
							bpf_set_error(cstate, "unknown LLC type name \"%s\"", (yyvsp[0].s));
							YYABORT;
						}
						CHECK_PTR_VAL(((yyval.rblk) = gen_llc_u_subtype(cstate, subtype)));
					}
				  }
				}
#line 3032 "grammar.c" /* yacc.c:1646  */
    break;

  case 145:
#line 815 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.rblk) = gen_llc_s_subtype(cstate, LLC_RNR))); }
#line 3038 "grammar.c" /* yacc.c:1646  */
    break;

  case 146:
#line 818 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = (int)(yyvsp[0].h); }
#line 3044 "grammar.c" /* yacc.c:1646  */
    break;

  case 147:
#line 819 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL((yyvsp[0].s));
				  if (pcapint_strcasecmp((yyvsp[0].s), "nods") == 0)
					(yyval.i) = IEEE80211_FC1_DIR_NODS;
				  else if (pcapint_strcasecmp((yyvsp[0].s), "tods") == 0)
					(yyval.i) = IEEE80211_FC1_DIR_TODS;
				  else if (pcapint_strcasecmp((yyvsp[0].s), "fromds") == 0)
					(yyval.i) = IEEE80211_FC1_DIR_FROMDS;
				  else if (pcapint_strcasecmp((yyvsp[0].s), "dstods") == 0)
					(yyval.i) = IEEE80211_FC1_DIR_DSTODS;
				  else {
					bpf_set_error(cstate, "unknown 802.11 direction");
					YYABORT;
				  }
				}
#line 3063 "grammar.c" /* yacc.c:1646  */
    break;

  case 148:
#line 835 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = (yyvsp[0].h); }
#line 3069 "grammar.c" /* yacc.c:1646  */
    break;

  case 149:
#line 836 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL((yyvsp[0].s)); CHECK_INT_VAL(((yyval.i) = pfreason_to_num(cstate, (yyvsp[0].s)))); }
#line 3075 "grammar.c" /* yacc.c:1646  */
    break;

  case 150:
#line 839 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL((yyvsp[0].s)); CHECK_INT_VAL(((yyval.i) = pfaction_to_num(cstate, (yyvsp[0].s)))); }
#line 3081 "grammar.c" /* yacc.c:1646  */
    break;

  case 151:
#line 842 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = BPF_JGT; }
#line 3087 "grammar.c" /* yacc.c:1646  */
    break;

  case 152:
#line 843 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = BPF_JGE; }
#line 3093 "grammar.c" /* yacc.c:1646  */
    break;

  case 153:
#line 844 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = BPF_JEQ; }
#line 3099 "grammar.c" /* yacc.c:1646  */
    break;

  case 154:
#line 846 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = BPF_JGT; }
#line 3105 "grammar.c" /* yacc.c:1646  */
    break;

  case 155:
#line 847 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = BPF_JGE; }
#line 3111 "grammar.c" /* yacc.c:1646  */
    break;

  case 156:
#line 848 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = BPF_JEQ; }
#line 3117 "grammar.c" /* yacc.c:1646  */
    break;

  case 157:
#line 850 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_loadi(cstate, (yyvsp[0].h)))); }
#line 3123 "grammar.c" /* yacc.c:1646  */
    break;

  case 159:
#line 853 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_load(cstate, (yyvsp[-3].i), (yyvsp[-1].a), 1))); }
#line 3129 "grammar.c" /* yacc.c:1646  */
    break;

  case 160:
#line 854 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_load(cstate, (yyvsp[-5].i), (yyvsp[-3].a), (yyvsp[-1].h)))); }
#line 3135 "grammar.c" /* yacc.c:1646  */
    break;

  case 161:
#line 855 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_arth(cstate, BPF_ADD, (yyvsp[-2].a), (yyvsp[0].a)))); }
#line 3141 "grammar.c" /* yacc.c:1646  */
    break;

  case 162:
#line 856 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_arth(cstate, BPF_SUB, (yyvsp[-2].a), (yyvsp[0].a)))); }
#line 3147 "grammar.c" /* yacc.c:1646  */
    break;

  case 163:
#line 857 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_arth(cstate, BPF_MUL, (yyvsp[-2].a), (yyvsp[0].a)))); }
#line 3153 "grammar.c" /* yacc.c:1646  */
    break;

  case 164:
#line 858 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_arth(cstate, BPF_DIV, (yyvsp[-2].a), (yyvsp[0].a)))); }
#line 3159 "grammar.c" /* yacc.c:1646  */
    break;

  case 165:
#line 859 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_arth(cstate, BPF_MOD, (yyvsp[-2].a), (yyvsp[0].a)))); }
#line 3165 "grammar.c" /* yacc.c:1646  */
    break;

  case 166:
#line 860 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_arth(cstate, BPF_AND, (yyvsp[-2].a), (yyvsp[0].a)))); }
#line 3171 "grammar.c" /* yacc.c:1646  */
    break;

  case 167:
#line 861 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_arth(cstate, BPF_OR, (yyvsp[-2].a), (yyvsp[0].a)))); }
#line 3177 "grammar.c" /* yacc.c:1646  */
    break;

  case 168:
#line 862 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_arth(cstate, BPF_XOR, (yyvsp[-2].a), (yyvsp[0].a)))); }
#line 3183 "grammar.c" /* yacc.c:1646  */
    break;

  case 169:
#line 863 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_arth(cstate, BPF_LSH, (yyvsp[-2].a), (yyvsp[0].a)))); }
#line 3189 "grammar.c" /* yacc.c:1646  */
    break;

  case 170:
#line 864 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_arth(cstate, BPF_RSH, (yyvsp[-2].a), (yyvsp[0].a)))); }
#line 3195 "grammar.c" /* yacc.c:1646  */
    break;

  case 171:
#line 865 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_neg(cstate, (yyvsp[0].a)))); }
#line 3201 "grammar.c" /* yacc.c:1646  */
    break;

  case 172:
#line 866 "grammar.y" /* yacc.c:1646  */
    { (yyval.a) = (yyvsp[-1].a); }
#line 3207 "grammar.c" /* yacc.c:1646  */
    break;

  case 173:
#line 867 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.a) = gen_loadlen(cstate))); }
#line 3213 "grammar.c" /* yacc.c:1646  */
    break;

  case 174:
#line 869 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = '&'; }
#line 3219 "grammar.c" /* yacc.c:1646  */
    break;

  case 175:
#line 870 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = '|'; }
#line 3225 "grammar.c" /* yacc.c:1646  */
    break;

  case 176:
#line 871 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = '<'; }
#line 3231 "grammar.c" /* yacc.c:1646  */
    break;

  case 177:
#line 872 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = '>'; }
#line 3237 "grammar.c" /* yacc.c:1646  */
    break;

  case 178:
#line 873 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = '='; }
#line 3243 "grammar.c" /* yacc.c:1646  */
    break;

  case 180:
#line 876 "grammar.y" /* yacc.c:1646  */
    { (yyval.h) = (yyvsp[-1].h); }
#line 3249 "grammar.c" /* yacc.c:1646  */
    break;

  case 181:
#line 878 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_LANE; }
#line 3255 "grammar.c" /* yacc.c:1646  */
    break;

  case 182:
#line 879 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_METAC;	}
#line 3261 "grammar.c" /* yacc.c:1646  */
    break;

  case 183:
#line 880 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_BCC; }
#line 3267 "grammar.c" /* yacc.c:1646  */
    break;

  case 184:
#line 881 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_OAMF4EC; }
#line 3273 "grammar.c" /* yacc.c:1646  */
    break;

  case 185:
#line 882 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_OAMF4SC; }
#line 3279 "grammar.c" /* yacc.c:1646  */
    break;

  case 186:
#line 883 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_SC; }
#line 3285 "grammar.c" /* yacc.c:1646  */
    break;

  case 187:
#line 884 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_ILMIC; }
#line 3291 "grammar.c" /* yacc.c:1646  */
    break;

  case 188:
#line 886 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_OAM; }
#line 3297 "grammar.c" /* yacc.c:1646  */
    break;

  case 189:
#line 887 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_OAMF4; }
#line 3303 "grammar.c" /* yacc.c:1646  */
    break;

  case 190:
#line 888 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_CONNECTMSG; }
#line 3309 "grammar.c" /* yacc.c:1646  */
    break;

  case 191:
#line 889 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = A_METACONNECT; }
#line 3315 "grammar.c" /* yacc.c:1646  */
    break;

  case 192:
#line 892 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).atmfieldtype = A_VPI; }
#line 3321 "grammar.c" /* yacc.c:1646  */
    break;

  case 193:
#line 893 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).atmfieldtype = A_VCI; }
#line 3327 "grammar.c" /* yacc.c:1646  */
    break;

  case 195:
#line 896 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.blk).b = gen_atmfield_code(cstate, (yyvsp[-2].blk).atmfieldtype, (yyvsp[0].h), (yyvsp[-1].i), 0))); }
#line 3333 "grammar.c" /* yacc.c:1646  */
    break;

  case 196:
#line 897 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.blk).b = gen_atmfield_code(cstate, (yyvsp[-2].blk).atmfieldtype, (yyvsp[0].h), (yyvsp[-1].i), 1))); }
#line 3339 "grammar.c" /* yacc.c:1646  */
    break;

  case 197:
#line 898 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = (yyvsp[-1].blk).b; (yyval.blk).q = qerr; }
#line 3345 "grammar.c" /* yacc.c:1646  */
    break;

  case 198:
#line 900 "grammar.y" /* yacc.c:1646  */
    {
	(yyval.blk).atmfieldtype = (yyvsp[-1].blk).atmfieldtype;
	if ((yyval.blk).atmfieldtype == A_VPI ||
	    (yyval.blk).atmfieldtype == A_VCI)
		CHECK_PTR_VAL(((yyval.blk).b = gen_atmfield_code(cstate, (yyval.blk).atmfieldtype, (yyvsp[0].h), BPF_JEQ, 0)));
	}
#line 3356 "grammar.c" /* yacc.c:1646  */
    break;

  case 200:
#line 908 "grammar.y" /* yacc.c:1646  */
    { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 3362 "grammar.c" /* yacc.c:1646  */
    break;

  case 201:
#line 911 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = M_FISU; }
#line 3368 "grammar.c" /* yacc.c:1646  */
    break;

  case 202:
#line 912 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = M_LSSU; }
#line 3374 "grammar.c" /* yacc.c:1646  */
    break;

  case 203:
#line 913 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = M_MSU; }
#line 3380 "grammar.c" /* yacc.c:1646  */
    break;

  case 204:
#line 914 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = MH_FISU; }
#line 3386 "grammar.c" /* yacc.c:1646  */
    break;

  case 205:
#line 915 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = MH_LSSU; }
#line 3392 "grammar.c" /* yacc.c:1646  */
    break;

  case 206:
#line 916 "grammar.y" /* yacc.c:1646  */
    { (yyval.i) = MH_MSU; }
#line 3398 "grammar.c" /* yacc.c:1646  */
    break;

  case 207:
#line 919 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = M_SIO; }
#line 3404 "grammar.c" /* yacc.c:1646  */
    break;

  case 208:
#line 920 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = M_OPC; }
#line 3410 "grammar.c" /* yacc.c:1646  */
    break;

  case 209:
#line 921 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = M_DPC; }
#line 3416 "grammar.c" /* yacc.c:1646  */
    break;

  case 210:
#line 922 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = M_SLS; }
#line 3422 "grammar.c" /* yacc.c:1646  */
    break;

  case 211:
#line 923 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = MH_SIO; }
#line 3428 "grammar.c" /* yacc.c:1646  */
    break;

  case 212:
#line 924 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = MH_OPC; }
#line 3434 "grammar.c" /* yacc.c:1646  */
    break;

  case 213:
#line 925 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = MH_DPC; }
#line 3440 "grammar.c" /* yacc.c:1646  */
    break;

  case 214:
#line 926 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).mtp3fieldtype = MH_SLS; }
#line 3446 "grammar.c" /* yacc.c:1646  */
    break;

  case 216:
#line 929 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.blk).b = gen_mtp3field_code(cstate, (yyvsp[-2].blk).mtp3fieldtype, (yyvsp[0].h), (yyvsp[-1].i), 0))); }
#line 3452 "grammar.c" /* yacc.c:1646  */
    break;

  case 217:
#line 930 "grammar.y" /* yacc.c:1646  */
    { CHECK_PTR_VAL(((yyval.blk).b = gen_mtp3field_code(cstate, (yyvsp[-2].blk).mtp3fieldtype, (yyvsp[0].h), (yyvsp[-1].i), 1))); }
#line 3458 "grammar.c" /* yacc.c:1646  */
    break;

  case 218:
#line 931 "grammar.y" /* yacc.c:1646  */
    { (yyval.blk).b = (yyvsp[-1].blk).b; (yyval.blk).q = qerr; }
#line 3464 "grammar.c" /* yacc.c:1646  */
    break;

  case 219:
#line 933 "grammar.y" /* yacc.c:1646  */
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
		CHECK_PTR_VAL(((yyval.blk).b = gen_mtp3field_code(cstate, (yyval.blk).mtp3fieldtype, (yyvsp[0].h), BPF_JEQ, 0)));
	}
#line 3481 "grammar.c" /* yacc.c:1646  */
    break;

  case 221:
#line 947 "grammar.y" /* yacc.c:1646  */
    { gen_or((yyvsp[-2].blk).b, (yyvsp[0].blk).b); (yyval.blk) = (yyvsp[0].blk); }
#line 3487 "grammar.c" /* yacc.c:1646  */
    break;


#line 3491 "grammar.c" /* yacc.c:1646  */
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
      yyerror (yyscanner, cstate, YY_("syntax error"));
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
        yyerror (yyscanner, cstate, yymsgp);
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
                      yytoken, &yylval, yyscanner, cstate);
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
                  yystos[yystate], yyvsp, yyscanner, cstate);
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
  yyerror (yyscanner, cstate, YY_("memory exhausted"));
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
                  yytoken, &yylval, yyscanner, cstate);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp, yyscanner, cstate);
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
#line 949 "grammar.y" /* yacc.c:1906  */

