/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

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
#line 349 "grammar.y" /* yacc.c:1909  */

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

#line 193 "grammar.h" /* yacc.c:1909  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int pcap_parse (void *yyscanner, compiler_state_t *cstate);

#endif /* !YY_PCAP_GRAMMAR_H_INCLUDED  */
