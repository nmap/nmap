/* A Bison parser, made by GNU Bison 2.5.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2011 Free Software Foundation, Inc.
   
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
     SIO = 362,
     OPC = 363,
     DPC = 364,
     SLS = 365,
     AND = 366,
     OR = 367,
     UMINUS = 368
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
#define SIO 362
#define OPC 363
#define DPC 364
#define SLS 365
#define AND 366
#define OR 367
#define UMINUS 368




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 2068 of yacc.c  */
#line 242 "grammar.y"

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



/* Line 2068 of yacc.c  */
#line 294 "y.tab.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE pcap_lval;


