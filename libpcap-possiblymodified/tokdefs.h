#ifndef YYERRCODE
#define YYERRCODE 256
#endif

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
extern YYSTYPE yylval;
