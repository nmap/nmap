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
#define PORTRANGE 264
#define LESS 265
#define GREATER 266
#define PROTO 267
#define PROTOCHAIN 268
#define CBYTE 269
#define ARP 270
#define RARP 271
#define IP 272
#define SCTP 273
#define TCP 274
#define UDP 275
#define ICMP 276
#define IGMP 277
#define IGRP 278
#define PIM 279
#define VRRP 280
#define ATALK 281
#define AARP 282
#define DECNET 283
#define LAT 284
#define SCA 285
#define MOPRC 286
#define MOPDL 287
#define TK_BROADCAST 288
#define TK_MULTICAST 289
#define NUM 290
#define INBOUND 291
#define OUTBOUND 292
#define PF_IFNAME 293
#define PF_RSET 294
#define PF_RNR 295
#define PF_SRNR 296
#define PF_REASON 297
#define PF_ACTION 298
#define LINK 299
#define GEQ 300
#define LEQ 301
#define NEQ 302
#define ID 303
#define EID 304
#define HID 305
#define HID6 306
#define AID 307
#define LSH 308
#define RSH 309
#define LEN 310
#define IPV6 311
#define ICMPV6 312
#define AH 313
#define ESP 314
#define VLAN 315
#define MPLS 316
#define PPPOED 317
#define PPPOES 318
#define ISO 319
#define ESIS 320
#define CLNP 321
#define ISIS 322
#define L1 323
#define L2 324
#define IIH 325
#define LSP 326
#define SNP 327
#define CSNP 328
#define PSNP 329
#define STP 330
#define IPX 331
#define NETBEUI 332
#define LANE 333
#define LLC 334
#define METAC 335
#define BCC 336
#define SC 337
#define ILMIC 338
#define OAMF4EC 339
#define OAMF4SC 340
#define OAM 341
#define OAMF4 342
#define CONNECTMSG 343
#define METACONNECT 344
#define VPI 345
#define VCI 346
#define RADIO 347
#define SIO 348
#define OPC 349
#define DPC 350
#define SLS 351
#define OR 352
#define AND 353
#define UMINUS 354
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
		int mtp3fieldtype;
		struct block *b;
	} blk;
	struct block *rblk;
} YYSTYPE;
extern YYSTYPE yylval;
