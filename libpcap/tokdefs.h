
/* A Bison parser, made by GNU Bison 2.4.1.  */

/* Skeleton interface for Bison's Yacc-like parsers in C
   
      Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.
   
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


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
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
     ATALK = 282,
     AARP = 283,
     DECNET = 284,
     LAT = 285,
     SCA = 286,
     MOPRC = 287,
     MOPDL = 288,
     TK_BROADCAST = 289,
     TK_MULTICAST = 290,
     NUM = 291,
     INBOUND = 292,
     OUTBOUND = 293,
     PF_IFNAME = 294,
     PF_RSET = 295,
     PF_RNR = 296,
     PF_SRNR = 297,
     PF_REASON = 298,
     PF_ACTION = 299,
     TYPE = 300,
     SUBTYPE = 301,
     DIR = 302,
     ADDR1 = 303,
     ADDR2 = 304,
     ADDR3 = 305,
     ADDR4 = 306,
     LINK = 307,
     GEQ = 308,
     LEQ = 309,
     NEQ = 310,
     ID = 311,
     EID = 312,
     HID = 313,
     HID6 = 314,
     AID = 315,
     LSH = 316,
     RSH = 317,
     LEN = 318,
     IPV6 = 319,
     ICMPV6 = 320,
     AH = 321,
     ESP = 322,
     VLAN = 323,
     MPLS = 324,
     PPPOED = 325,
     PPPOES = 326,
     ISO = 327,
     ESIS = 328,
     CLNP = 329,
     ISIS = 330,
     L1 = 331,
     L2 = 332,
     IIH = 333,
     LSP = 334,
     SNP = 335,
     CSNP = 336,
     PSNP = 337,
     STP = 338,
     IPX = 339,
     NETBEUI = 340,
     LANE = 341,
     LLC = 342,
     METAC = 343,
     BCC = 344,
     SC = 345,
     ILMIC = 346,
     OAMF4EC = 347,
     OAMF4SC = 348,
     OAM = 349,
     OAMF4 = 350,
     CONNECTMSG = 351,
     METACONNECT = 352,
     VPI = 353,
     VCI = 354,
     RADIO = 355,
     FISU = 356,
     LSSU = 357,
     MSU = 358,
     SIO = 359,
     OPC = 360,
     DPC = 361,
     SLS = 362,
     AND = 363,
     OR = 364,
     UMINUS = 365
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
#define ATALK 282
#define AARP 283
#define DECNET 284
#define LAT 285
#define SCA 286
#define MOPRC 287
#define MOPDL 288
#define TK_BROADCAST 289
#define TK_MULTICAST 290
#define NUM 291
#define INBOUND 292
#define OUTBOUND 293
#define PF_IFNAME 294
#define PF_RSET 295
#define PF_RNR 296
#define PF_SRNR 297
#define PF_REASON 298
#define PF_ACTION 299
#define TYPE 300
#define SUBTYPE 301
#define DIR 302
#define ADDR1 303
#define ADDR2 304
#define ADDR3 305
#define ADDR4 306
#define LINK 307
#define GEQ 308
#define LEQ 309
#define NEQ 310
#define ID 311
#define EID 312
#define HID 313
#define HID6 314
#define AID 315
#define LSH 316
#define RSH 317
#define LEN 318
#define IPV6 319
#define ICMPV6 320
#define AH 321
#define ESP 322
#define VLAN 323
#define MPLS 324
#define PPPOED 325
#define PPPOES 326
#define ISO 327
#define ESIS 328
#define CLNP 329
#define ISIS 330
#define L1 331
#define L2 332
#define IIH 333
#define LSP 334
#define SNP 335
#define CSNP 336
#define PSNP 337
#define STP 338
#define IPX 339
#define NETBEUI 340
#define LANE 341
#define LLC 342
#define METAC 343
#define BCC 344
#define SC 345
#define ILMIC 346
#define OAMF4EC 347
#define OAMF4SC 348
#define OAM 349
#define OAMF4 350
#define CONNECTMSG 351
#define METACONNECT 352
#define VPI 353
#define VCI 354
#define RADIO 355
#define FISU 356
#define LSSU 357
#define MSU 358
#define SIO 359
#define OPC 360
#define DPC 361
#define SLS 362
#define AND 363
#define OR 364
#define UMINUS 365




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 1676 of yacc.c  */
#line 241 "grammar.y"

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



/* Line 1676 of yacc.c  */
#line 290 "y.tab.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE pcap_lval;


