/*#define CHASE_CHAIN*/
/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998
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
    "@(#) $Header: /tcpdump/master/libpcap/gencode.c,v 1.309 2008-12-23 20:13:29 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include <pcap-stdinc.h>
#else /* WIN32 */
#if HAVE_INTTYPES_H
#include <inttypes.h>
#elif HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#endif /* WIN32 */

/*
 * XXX - why was this included even on UNIX?
 */
#ifdef __MINGW32__
#include "ip6_misc.h"
#endif

#ifndef WIN32

#ifdef __NetBSD__
#include <sys/param.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#endif /* WIN32 */

#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <setjmp.h>
#include <stdarg.h>

#ifdef MSDOS
#include "pcap-dos.h"
#endif

#include "pcap-int.h"

#include "ethertype.h"
#include "nlpid.h"
#include "llc.h"
#include "gencode.h"
#include "ieee80211.h"
#include "atmuni31.h"
#include "sunatmpos.h"
#include "ppp.h"
#include "pcap/sll.h"
#include "pcap/ipnet.h"
#include "arcnet.h"
#if defined(linux) && defined(PF_PACKET) && defined(SO_ATTACH_FILTER)
#include <linux/types.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#endif
#ifdef HAVE_NET_PFVAR_H
#include <sys/socket.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <net/if_pflog.h>
#endif
#ifndef offsetof
#define offsetof(s, e) ((size_t)&((s *)0)->e)
#endif
#ifdef INET6
#ifndef WIN32
#include <netdb.h>	/* for "struct addrinfo" */
#endif /* WIN32 */
#endif /*INET6*/
#include <pcap/namedb.h>

#define ETHERMTU	1500

#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#define JMP(c) ((c)|BPF_JMP|BPF_K)

/* Locals */
static jmp_buf top_ctx;
static pcap_t *bpf_pcap;

/* Hack for updating VLAN, MPLS, and PPPoE offsets. */
#ifdef WIN32
static u_int	orig_linktype = (u_int)-1, orig_nl = (u_int)-1, label_stack_depth = (u_int)-1;
#else
static u_int	orig_linktype = -1U, orig_nl = -1U, label_stack_depth = -1U;
#endif

/* XXX */
static int	pcap_fddipad;

/* VARARGS */
void
bpf_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (bpf_pcap != NULL)
		(void)vsnprintf(pcap_geterr(bpf_pcap), PCAP_ERRBUF_SIZE,
		    fmt, ap);
	va_end(ap);
	longjmp(top_ctx, 1);
	/* NOTREACHED */
}

static void init_linktype(pcap_t *);

static void init_regs(void);
static int alloc_reg(void);
static void free_reg(int);

static struct block *root;

/*
 * Value passed to gen_load_a() to indicate what the offset argument
 * is relative to.
 */
enum e_offrel {
	OR_PACKET,	/* relative to the beginning of the packet */
	OR_LINK,	/* relative to the beginning of the link-layer header */
	OR_MACPL,	/* relative to the end of the MAC-layer header */
	OR_NET,		/* relative to the network-layer header */
	OR_NET_NOSNAP,	/* relative to the network-layer header, with no SNAP header at the link layer */
	OR_TRAN_IPV4,	/* relative to the transport-layer header, with IPv4 network layer */
	OR_TRAN_IPV6	/* relative to the transport-layer header, with IPv6 network layer */
};

#ifdef INET6
/*
 * As errors are handled by a longjmp, anything allocated must be freed
 * in the longjmp handler, so it must be reachable from that handler.
 * One thing that's allocated is the result of pcap_nametoaddrinfo();
 * it must be freed with freeaddrinfo().  This variable points to any
 * addrinfo structure that would need to be freed.
 */
static struct addrinfo *ai;
#endif

/*
 * We divy out chunks of memory rather than call malloc each time so
 * we don't have to worry about leaking memory.  It's probably
 * not a big deal if all this memory was wasted but if this ever
 * goes into a library that would probably not be a good idea.
 *
 * XXX - this *is* in a library....
 */
#define NCHUNKS 16
#define CHUNK0SIZE 1024
struct chunk {
	u_int n_left;
	void *m;
};

static struct chunk chunks[NCHUNKS];
static int cur_chunk;

static void *newchunk(u_int);
static void freechunks(void);
static inline struct block *new_block(int);
static inline struct slist *new_stmt(int);
static struct block *gen_retblk(int);
static inline void syntax(void);

static void backpatch(struct block *, struct block *);
static void merge(struct block *, struct block *);
static struct block *gen_cmp(enum e_offrel, u_int, u_int, bpf_int32);
static struct block *gen_cmp_gt(enum e_offrel, u_int, u_int, bpf_int32);
static struct block *gen_cmp_ge(enum e_offrel, u_int, u_int, bpf_int32);
static struct block *gen_cmp_lt(enum e_offrel, u_int, u_int, bpf_int32);
static struct block *gen_cmp_le(enum e_offrel, u_int, u_int, bpf_int32);
static struct block *gen_mcmp(enum e_offrel, u_int, u_int, bpf_int32,
    bpf_u_int32);
static struct block *gen_bcmp(enum e_offrel, u_int, u_int, const u_char *);
static struct block *gen_ncmp(enum e_offrel, bpf_u_int32, bpf_u_int32,
    bpf_u_int32, bpf_u_int32, int, bpf_int32);
static struct slist *gen_load_llrel(u_int, u_int);
static struct slist *gen_load_macplrel(u_int, u_int);
static struct slist *gen_load_a(enum e_offrel, u_int, u_int);
static struct slist *gen_loadx_iphdrlen(void);
static struct block *gen_uncond(int);
static inline struct block *gen_true(void);
static inline struct block *gen_false(void);
static struct block *gen_ether_linktype(int);
static struct block *gen_ipnet_linktype(int);
static struct block *gen_linux_sll_linktype(int);
static struct slist *gen_load_prism_llprefixlen(void);
static struct slist *gen_load_avs_llprefixlen(void);
static struct slist *gen_load_radiotap_llprefixlen(void);
static struct slist *gen_load_ppi_llprefixlen(void);
static void insert_compute_vloffsets(struct block *);
static struct slist *gen_llprefixlen(void);
static struct slist *gen_off_macpl(void);
static int ethertype_to_ppptype(int);
static struct block *gen_linktype(int);
static struct block *gen_snap(bpf_u_int32, bpf_u_int32);
static struct block *gen_llc_linktype(int);
static struct block *gen_hostop(bpf_u_int32, bpf_u_int32, int, int, u_int, u_int);
#ifdef INET6
static struct block *gen_hostop6(struct in6_addr *, struct in6_addr *, int, int, u_int, u_int);
#endif
static struct block *gen_ahostop(const u_char *, int);
static struct block *gen_ehostop(const u_char *, int);
static struct block *gen_fhostop(const u_char *, int);
static struct block *gen_thostop(const u_char *, int);
static struct block *gen_wlanhostop(const u_char *, int);
static struct block *gen_ipfchostop(const u_char *, int);
static struct block *gen_dnhostop(bpf_u_int32, int);
static struct block *gen_mpls_linktype(int);
static struct block *gen_host(bpf_u_int32, bpf_u_int32, int, int, int);
#ifdef INET6
static struct block *gen_host6(struct in6_addr *, struct in6_addr *, int, int, int);
#endif
#ifndef INET6
static struct block *gen_gateway(const u_char *, bpf_u_int32 **, int, int);
#endif
static struct block *gen_ipfrag(void);
static struct block *gen_portatom(int, bpf_int32);
static struct block *gen_portrangeatom(int, bpf_int32, bpf_int32);
static struct block *gen_portatom6(int, bpf_int32);
static struct block *gen_portrangeatom6(int, bpf_int32, bpf_int32);
struct block *gen_portop(int, int, int);
static struct block *gen_port(int, int, int);
struct block *gen_portrangeop(int, int, int, int);
static struct block *gen_portrange(int, int, int, int);
struct block *gen_portop6(int, int, int);
static struct block *gen_port6(int, int, int);
struct block *gen_portrangeop6(int, int, int, int);
static struct block *gen_portrange6(int, int, int, int);
static int lookup_proto(const char *, int);
static struct block *gen_protochain(int, int, int);
static struct block *gen_proto(int, int, int);
static struct slist *xfer_to_x(struct arth *);
static struct slist *xfer_to_a(struct arth *);
static struct block *gen_mac_multicast(int);
static struct block *gen_len(int, int);
static struct block *gen_check_802_11_data_frame(void);

static struct block *gen_ppi_dlt_check(void);
static struct block *gen_msg_abbrev(int type);

static void *
newchunk(n)
	u_int n;
{
	struct chunk *cp;
	int k;
	size_t size;

#ifndef __NetBSD__
	/* XXX Round up to nearest long. */
	n = (n + sizeof(long) - 1) & ~(sizeof(long) - 1);
#else
	/* XXX Round up to structure boundary. */
	n = ALIGN(n);
#endif

	cp = &chunks[cur_chunk];
	if (n > cp->n_left) {
		++cp, k = ++cur_chunk;
		if (k >= NCHUNKS)
			bpf_error("out of memory");
		size = CHUNK0SIZE << k;
		cp->m = (void *)malloc(size);
		if (cp->m == NULL)
			bpf_error("out of memory");
		memset((char *)cp->m, 0, size);
		cp->n_left = size;
		if (n > size)
			bpf_error("out of memory");
	}
	cp->n_left -= n;
	return (void *)((char *)cp->m + cp->n_left);
}

static void
freechunks()
{
	int i;

	cur_chunk = 0;
	for (i = 0; i < NCHUNKS; ++i)
		if (chunks[i].m != NULL) {
			free(chunks[i].m);
			chunks[i].m = NULL;
		}
}

/*
 * A strdup whose allocations are freed after code generation is over.
 */
char *
sdup(s)
	register const char *s;
{
	int n = strlen(s) + 1;
	char *cp = newchunk(n);

	strlcpy(cp, s, n);
	return (cp);
}

static inline struct block *
new_block(code)
	int code;
{
	struct block *p;

	p = (struct block *)newchunk(sizeof(*p));
	p->s.code = code;
	p->head = p;

	return p;
}

static inline struct slist *
new_stmt(code)
	int code;
{
	struct slist *p;

	p = (struct slist *)newchunk(sizeof(*p));
	p->s.code = code;

	return p;
}

static struct block *
gen_retblk(v)
	int v;
{
	struct block *b = new_block(BPF_RET|BPF_K);

	b->s.k = v;
	return b;
}

static inline void
syntax()
{
	bpf_error("syntax error in filter expression");
}

static bpf_u_int32 netmask;
static int snaplen;
int no_optimize;
#ifdef WIN32
static int
pcap_compile_unsafe(pcap_t *p, struct bpf_program *program,
	     const char *buf, int optimize, bpf_u_int32 mask);

int
pcap_compile(pcap_t *p, struct bpf_program *program,
	     const char *buf, int optimize, bpf_u_int32 mask)
{
	int result;

	EnterCriticalSection(&g_PcapCompileCriticalSection);

	result = pcap_compile_unsafe(p, program, buf, optimize, mask);

	LeaveCriticalSection(&g_PcapCompileCriticalSection);
	
	return result;
}

static int
pcap_compile_unsafe(pcap_t *p, struct bpf_program *program,
	     const char *buf, int optimize, bpf_u_int32 mask)
#else /* WIN32 */
int
pcap_compile(pcap_t *p, struct bpf_program *program,
	     const char *buf, int optimize, bpf_u_int32 mask)
#endif /* WIN32 */
{
	extern int n_errors;
	const char * volatile xbuf = buf;
	u_int len;

	/*
	 * If this pcap_t hasn't been activated, it doesn't have a
	 * link-layer type, so we can't use it.
	 */
	if (!p->activated) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "not-yet-activated pcap_t passed to pcap_compile");
		return (-1);
	}
	no_optimize = 0;
	n_errors = 0;
	root = NULL;
	bpf_pcap = p;
	init_regs();
	if (setjmp(top_ctx)) {
#ifdef INET6
		if (ai != NULL) {
			freeaddrinfo(ai);
			ai = NULL;
		}
#endif
		lex_cleanup();
		freechunks();
		return (-1);
	}

	netmask = mask;

	snaplen = pcap_snapshot(p);
	if (snaplen == 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			 "snaplen of 0 rejects all packets");
		return -1;
	}

	lex_init(xbuf ? xbuf : "");
	init_linktype(p);
	(void)pcap_parse();

	if (n_errors)
		syntax();

	if (root == NULL)
		root = gen_retblk(snaplen);

	if (optimize && !no_optimize) {
		bpf_optimize(&root);
		if (root == NULL ||
		    (root->s.code == (BPF_RET|BPF_K) && root->s.k == 0))
			bpf_error("expression rejects all packets");
	}
	program->bf_insns = icode_to_fcode(root, &len);
	program->bf_len = len;

	lex_cleanup();
	freechunks();
	return (0);
}

/*
 * entry point for using the compiler with no pcap open
 * pass in all the stuff that is needed explicitly instead.
 */
int
pcap_compile_nopcap(int snaplen_arg, int linktype_arg,
		    struct bpf_program *program,
	     const char *buf, int optimize, bpf_u_int32 mask)
{
	pcap_t *p;
	int ret;

	p = pcap_open_dead(linktype_arg, snaplen_arg);
	if (p == NULL)
		return (-1);
	ret = pcap_compile(p, program, buf, optimize, mask);
	pcap_close(p);
	return (ret);
}

/*
 * Clean up a "struct bpf_program" by freeing all the memory allocated
 * in it.
 */
void
pcap_freecode(struct bpf_program *program)
{
	program->bf_len = 0;
	if (program->bf_insns != NULL) {
		free((char *)program->bf_insns);
		program->bf_insns = NULL;
	}
}

/*
 * Backpatch the blocks in 'list' to 'target'.  The 'sense' field indicates
 * which of the jt and jf fields has been resolved and which is a pointer
 * back to another unresolved block (or nil).  At least one of the fields
 * in each block is already resolved.
 */
static void
backpatch(list, target)
	struct block *list, *target;
{
	struct block *next;

	while (list) {
		if (!list->sense) {
			next = JT(list);
			JT(list) = target;
		} else {
			next = JF(list);
			JF(list) = target;
		}
		list = next;
	}
}

/*
 * Merge the lists in b0 and b1, using the 'sense' field to indicate
 * which of jt and jf is the link.
 */
static void
merge(b0, b1)
	struct block *b0, *b1;
{
	register struct block **p = &b0;

	/* Find end of list. */
	while (*p)
		p = !((*p)->sense) ? &JT(*p) : &JF(*p);

	/* Concatenate the lists. */
	*p = b1;
}

void
finish_parse(p)
	struct block *p;
{
	struct block *ppi_dlt_check;

	/*
	 * Insert before the statements of the first (root) block any
	 * statements needed to load the lengths of any variable-length
	 * headers into registers.
	 *
	 * XXX - a fancier strategy would be to insert those before the
	 * statements of all blocks that use those lengths and that
	 * have no predecessors that use them, so that we only compute
	 * the lengths if we need them.  There might be even better
	 * approaches than that.
	 *
	 * However, those strategies would be more complicated, and
	 * as we don't generate code to compute a length if the
	 * program has no tests that use the length, and as most
	 * tests will probably use those lengths, we would just
	 * postpone computing the lengths so that it's not done
	 * for tests that fail early, and it's not clear that's
	 * worth the effort.
	 */
	insert_compute_vloffsets(p->head);
	
	/*
	 * For DLT_PPI captures, generate a check of the per-packet
	 * DLT value to make sure it's DLT_IEEE802_11.
	 */
	ppi_dlt_check = gen_ppi_dlt_check();
	if (ppi_dlt_check != NULL)
		gen_and(ppi_dlt_check, p);

	backpatch(p, gen_retblk(snaplen));
	p->sense = !p->sense;
	backpatch(p, gen_retblk(0));
	root = p->head;
}

void
gen_and(b0, b1)
	struct block *b0, *b1;
{
	backpatch(b0, b1->head);
	b0->sense = !b0->sense;
	b1->sense = !b1->sense;
	merge(b1, b0);
	b1->sense = !b1->sense;
	b1->head = b0->head;
}

void
gen_or(b0, b1)
	struct block *b0, *b1;
{
	b0->sense = !b0->sense;
	backpatch(b0, b1->head);
	b0->sense = !b0->sense;
	merge(b1, b0);
	b1->head = b0->head;
}

void
gen_not(b)
	struct block *b;
{
	b->sense = !b->sense;
}

static struct block *
gen_cmp(offrel, offset, size, v)
	enum e_offrel offrel;
	u_int offset, size;
	bpf_int32 v;
{
	return gen_ncmp(offrel, offset, size, 0xffffffff, BPF_JEQ, 0, v);
}

static struct block *
gen_cmp_gt(offrel, offset, size, v)
	enum e_offrel offrel;
	u_int offset, size;
	bpf_int32 v;
{
	return gen_ncmp(offrel, offset, size, 0xffffffff, BPF_JGT, 0, v);
}

static struct block *
gen_cmp_ge(offrel, offset, size, v)
	enum e_offrel offrel;
	u_int offset, size;
	bpf_int32 v;
{
	return gen_ncmp(offrel, offset, size, 0xffffffff, BPF_JGE, 0, v);
}

static struct block *
gen_cmp_lt(offrel, offset, size, v)
	enum e_offrel offrel;
	u_int offset, size;
	bpf_int32 v;
{
	return gen_ncmp(offrel, offset, size, 0xffffffff, BPF_JGE, 1, v);
}

static struct block *
gen_cmp_le(offrel, offset, size, v)
	enum e_offrel offrel;
	u_int offset, size;
	bpf_int32 v;
{
	return gen_ncmp(offrel, offset, size, 0xffffffff, BPF_JGT, 1, v);
}

static struct block *
gen_mcmp(offrel, offset, size, v, mask)
	enum e_offrel offrel;
	u_int offset, size;
	bpf_int32 v;
	bpf_u_int32 mask;
{
	return gen_ncmp(offrel, offset, size, mask, BPF_JEQ, 0, v);
}

static struct block *
gen_bcmp(offrel, offset, size, v)
	enum e_offrel offrel;
	register u_int offset, size;
	register const u_char *v;
{
	register struct block *b, *tmp;

	b = NULL;
	while (size >= 4) {
		register const u_char *p = &v[size - 4];
		bpf_int32 w = ((bpf_int32)p[0] << 24) |
		    ((bpf_int32)p[1] << 16) | ((bpf_int32)p[2] << 8) | p[3];

		tmp = gen_cmp(offrel, offset + size - 4, BPF_W, w);
		if (b != NULL)
			gen_and(b, tmp);
		b = tmp;
		size -= 4;
	}
	while (size >= 2) {
		register const u_char *p = &v[size - 2];
		bpf_int32 w = ((bpf_int32)p[0] << 8) | p[1];

		tmp = gen_cmp(offrel, offset + size - 2, BPF_H, w);
		if (b != NULL)
			gen_and(b, tmp);
		b = tmp;
		size -= 2;
	}
	if (size > 0) {
		tmp = gen_cmp(offrel, offset, BPF_B, (bpf_int32)v[0]);
		if (b != NULL)
			gen_and(b, tmp);
		b = tmp;
	}
	return b;
}

/*
 * AND the field of size "size" at offset "offset" relative to the header
 * specified by "offrel" with "mask", and compare it with the value "v"
 * with the test specified by "jtype"; if "reverse" is true, the test
 * should test the opposite of "jtype".
 */
static struct block *
gen_ncmp(offrel, offset, size, mask, jtype, reverse, v)
	enum e_offrel offrel;
	bpf_int32 v;
	bpf_u_int32 offset, size, mask, jtype;
	int reverse;
{
	struct slist *s, *s2;
	struct block *b;

	s = gen_load_a(offrel, offset, size);

	if (mask != 0xffffffff) {
		s2 = new_stmt(BPF_ALU|BPF_AND|BPF_K);
		s2->s.k = mask;
		sappend(s, s2);
	}

	b = new_block(JMP(jtype));
	b->stmts = s;
	b->s.k = v;
	if (reverse && (jtype == BPF_JGT || jtype == BPF_JGE))
		gen_not(b);
	return b;
}

/*
 * Various code constructs need to know the layout of the data link
 * layer.  These variables give the necessary offsets from the beginning
 * of the packet data.
 */

/*
 * This is the offset of the beginning of the link-layer header from
 * the beginning of the raw packet data.
 *
 * It's usually 0, except for 802.11 with a fixed-length radio header.
 * (For 802.11 with a variable-length radio header, we have to generate
 * code to compute that offset; off_ll is 0 in that case.)
 */
static u_int off_ll;

/*
 * If there's a variable-length header preceding the link-layer header,
 * "reg_off_ll" is the register number for a register containing the
 * length of that header, and therefore the offset of the link-layer
 * header from the beginning of the raw packet data.  Otherwise,
 * "reg_off_ll" is -1.
 */
static int reg_off_ll;

/*
 * This is the offset of the beginning of the MAC-layer header from
 * the beginning of the link-layer header.
 * It's usually 0, except for ATM LANE, where it's the offset, relative
 * to the beginning of the raw packet data, of the Ethernet header, and
 * for Ethernet with various additional information.
 */
static u_int off_mac;

/*
 * This is the offset of the beginning of the MAC-layer payload,
 * from the beginning of the raw packet data.
 *
 * I.e., it's the sum of the length of the link-layer header (without,
 * for example, any 802.2 LLC header, so it's the MAC-layer
 * portion of that header), plus any prefix preceding the
 * link-layer header.
 */
static u_int off_macpl;

/*
 * This is 1 if the offset of the beginning of the MAC-layer payload
 * from the beginning of the link-layer header is variable-length.
 */
static int off_macpl_is_variable;

/*
 * If the link layer has variable_length headers, "reg_off_macpl"
 * is the register number for a register containing the length of the
 * link-layer header plus the length of any variable-length header
 * preceding the link-layer header.  Otherwise, "reg_off_macpl"
 * is -1.
 */
static int reg_off_macpl;

/*
 * "off_linktype" is the offset to information in the link-layer header
 * giving the packet type.  This offset is relative to the beginning
 * of the link-layer header (i.e., it doesn't include off_ll).
 *
 * For Ethernet, it's the offset of the Ethernet type field.
 *
 * For link-layer types that always use 802.2 headers, it's the
 * offset of the LLC header.
 *
 * For PPP, it's the offset of the PPP type field.
 *
 * For Cisco HDLC, it's the offset of the CHDLC type field.
 *
 * For BSD loopback, it's the offset of the AF_ value.
 *
 * For Linux cooked sockets, it's the offset of the type field.
 *
 * It's set to -1 for no encapsulation, in which case, IP is assumed.
 */
static u_int off_linktype;

/*
 * TRUE if "pppoes" appeared in the filter; it causes link-layer type
 * checks to check the PPP header, assumed to follow a LAN-style link-
 * layer header and a PPPoE session header.
 */
static int is_pppoes = 0;

/*
 * TRUE if the link layer includes an ATM pseudo-header.
 */
static int is_atm = 0;

/*
 * TRUE if "lane" appeared in the filter; it causes us to generate
 * code that assumes LANE rather than LLC-encapsulated traffic in SunATM.
 */
static int is_lane = 0;

/*
 * These are offsets for the ATM pseudo-header.
 */
static u_int off_vpi;
static u_int off_vci;
static u_int off_proto;

/*
 * These are offsets for the MTP2 fields.
 */
static u_int off_li;
static u_int off_li_hsl;

/*
 * These are offsets for the MTP3 fields.
 */
static u_int off_sio;
static u_int off_opc;
static u_int off_dpc;
static u_int off_sls;

/*
 * This is the offset of the first byte after the ATM pseudo_header,
 * or -1 if there is no ATM pseudo-header.
 */
static u_int off_payload;

/*
 * These are offsets to the beginning of the network-layer header.
 * They are relative to the beginning of the MAC-layer payload (i.e.,
 * they don't include off_ll or off_macpl).
 *
 * If the link layer never uses 802.2 LLC:
 *
 *	"off_nl" and "off_nl_nosnap" are the same.
 *
 * If the link layer always uses 802.2 LLC:
 *
 *	"off_nl" is the offset if there's a SNAP header following
 *	the 802.2 header;
 *
 *	"off_nl_nosnap" is the offset if there's no SNAP header.
 *
 * If the link layer is Ethernet:
 *
 *	"off_nl" is the offset if the packet is an Ethernet II packet
 *	(we assume no 802.3+802.2+SNAP);
 *
 *	"off_nl_nosnap" is the offset if the packet is an 802.3 packet
 *	with an 802.2 header following it.
 */
static u_int off_nl;
static u_int off_nl_nosnap;

static int linktype;

static void
init_linktype(p)
	pcap_t *p;
{
	linktype = pcap_datalink(p);
	pcap_fddipad = p->fddipad;

	/*
	 * Assume it's not raw ATM with a pseudo-header, for now.
	 */
	off_mac = 0;
	is_atm = 0;
	is_lane = 0;
	off_vpi = -1;
	off_vci = -1;
	off_proto = -1;
	off_payload = -1;

	/*
	 * And that we're not doing PPPoE.
	 */
	is_pppoes = 0;

	/*
	 * And assume we're not doing SS7.
	 */
	off_li = -1;
	off_li_hsl = -1;
	off_sio = -1;
	off_opc = -1;
	off_dpc = -1;
	off_sls = -1;

	/*
	 * Also assume it's not 802.11.
	 */
	off_ll = 0;
	off_macpl = 0;
	off_macpl_is_variable = 0;

	orig_linktype = -1;
	orig_nl = -1;
        label_stack_depth = 0;

	reg_off_ll = -1;
	reg_off_macpl = -1;

	switch (linktype) {

	case DLT_ARCNET:
		off_linktype = 2;
		off_macpl = 6;
		off_nl = 0;		/* XXX in reality, variable! */
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_ARCNET_LINUX:
		off_linktype = 4;
		off_macpl = 8;
		off_nl = 0;		/* XXX in reality, variable! */
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_EN10MB:
		off_linktype = 12;
		off_macpl = 14;		/* Ethernet header length */
		off_nl = 0;		/* Ethernet II */
		off_nl_nosnap = 3;	/* 802.3+802.2 */
		return;

	case DLT_SLIP:
		/*
		 * SLIP doesn't have a link level type.  The 16 byte
		 * header is hacked into our SLIP driver.
		 */
		off_linktype = -1;
		off_macpl = 16;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_SLIP_BSDOS:
		/* XXX this may be the same as the DLT_PPP_BSDOS case */
		off_linktype = -1;
		/* XXX end */
		off_macpl = 24;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_NULL:
	case DLT_LOOP:
		off_linktype = 0;
		off_macpl = 4;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_ENC:
		off_linktype = 0;
		off_macpl = 12;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_PPP:
	case DLT_PPP_PPPD:
	case DLT_C_HDLC:		/* BSD/OS Cisco HDLC */
	case DLT_PPP_SERIAL:		/* NetBSD sync/async serial PPP */
		off_linktype = 2;
		off_macpl = 4;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_PPP_ETHER:
		/*
		 * This does no include the Ethernet header, and
		 * only covers session state.
		 */
		off_linktype = 6;
		off_macpl = 8;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_PPP_BSDOS:
		off_linktype = 5;
		off_macpl = 24;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_FDDI:
		/*
		 * FDDI doesn't really have a link-level type field.
		 * We set "off_linktype" to the offset of the LLC header.
		 *
		 * To check for Ethernet types, we assume that SSAP = SNAP
		 * is being used and pick out the encapsulated Ethernet type.
		 * XXX - should we generate code to check for SNAP?
		 */
		off_linktype = 13;
		off_linktype += pcap_fddipad;
		off_macpl = 13;		/* FDDI MAC header length */
		off_macpl += pcap_fddipad;
		off_nl = 8;		/* 802.2+SNAP */
		off_nl_nosnap = 3;	/* 802.2 */
		return;

	case DLT_IEEE802:
		/*
		 * Token Ring doesn't really have a link-level type field.
		 * We set "off_linktype" to the offset of the LLC header.
		 *
		 * To check for Ethernet types, we assume that SSAP = SNAP
		 * is being used and pick out the encapsulated Ethernet type.
		 * XXX - should we generate code to check for SNAP?
		 *
		 * XXX - the header is actually variable-length.
		 * Some various Linux patched versions gave 38
		 * as "off_linktype" and 40 as "off_nl"; however,
		 * if a token ring packet has *no* routing
		 * information, i.e. is not source-routed, the correct
		 * values are 20 and 22, as they are in the vanilla code.
		 *
		 * A packet is source-routed iff the uppermost bit
		 * of the first byte of the source address, at an
		 * offset of 8, has the uppermost bit set.  If the
		 * packet is source-routed, the total number of bytes
		 * of routing information is 2 plus bits 0x1F00 of
		 * the 16-bit value at an offset of 14 (shifted right
		 * 8 - figure out which byte that is).
		 */
		off_linktype = 14;
		off_macpl = 14;		/* Token Ring MAC header length */
		off_nl = 8;		/* 802.2+SNAP */
		off_nl_nosnap = 3;	/* 802.2 */
		return;

	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
		/*
		 * 802.11 doesn't really have a link-level type field.
		 * We set "off_linktype" to the offset of the LLC header.
		 *
		 * To check for Ethernet types, we assume that SSAP = SNAP
		 * is being used and pick out the encapsulated Ethernet type.
		 * XXX - should we generate code to check for SNAP?
		 *
		 * We also handle variable-length radio headers here.
		 * The Prism header is in theory variable-length, but in
		 * practice it's always 144 bytes long.  However, some
		 * drivers on Linux use ARPHRD_IEEE80211_PRISM, but
		 * sometimes or always supply an AVS header, so we
		 * have to check whether the radio header is a Prism
		 * header or an AVS header, so, in practice, it's
		 * variable-length.
		 */
		off_linktype = 24;
		off_macpl = 0;		/* link-layer header is variable-length */
		off_macpl_is_variable = 1;
		off_nl = 8;		/* 802.2+SNAP */
		off_nl_nosnap = 3;	/* 802.2 */
		return;

	case DLT_PPI:
		/* 
		 * At the moment we treat PPI the same way that we treat
		 * normal Radiotap encoded packets. The difference is in
		 * the function that generates the code at the beginning
		 * to compute the header length.  Since this code generator
		 * of PPI supports bare 802.11 encapsulation only (i.e.
		 * the encapsulated DLT should be DLT_IEEE802_11) we
		 * generate code to check for this too.
		 */
		off_linktype = 24;
		off_macpl = 0;		/* link-layer header is variable-length */
		off_macpl_is_variable = 1;
		off_nl = 8;		/* 802.2+SNAP */
		off_nl_nosnap = 3;	/* 802.2 */
		return;

	case DLT_ATM_RFC1483:
	case DLT_ATM_CLIP:	/* Linux ATM defines this */
		/*
		 * assume routed, non-ISO PDUs
		 * (i.e., LLC = 0xAA-AA-03, OUT = 0x00-00-00)
		 *
		 * XXX - what about ISO PDUs, e.g. CLNP, ISIS, ESIS,
		 * or PPP with the PPP NLPID (e.g., PPPoA)?  The
		 * latter would presumably be treated the way PPPoE
		 * should be, so you can do "pppoe and udp port 2049"
		 * or "pppoa and tcp port 80" and have it check for
		 * PPPo{A,E} and a PPP protocol of IP and....
		 */
		off_linktype = 0;
		off_macpl = 0;		/* packet begins with LLC header */
		off_nl = 8;		/* 802.2+SNAP */
		off_nl_nosnap = 3;	/* 802.2 */
		return;

	case DLT_SUNATM:
		/*
		 * Full Frontal ATM; you get AALn PDUs with an ATM
		 * pseudo-header.
		 */
		is_atm = 1;
		off_vpi = SUNATM_VPI_POS;
		off_vci = SUNATM_VCI_POS;
		off_proto = PROTO_POS;
		off_mac = -1;	/* assume LLC-encapsulated, so no MAC-layer header */
		off_payload = SUNATM_PKT_BEGIN_POS;
		off_linktype = off_payload;
		off_macpl = off_payload;	/* if LLC-encapsulated */
		off_nl = 8;		/* 802.2+SNAP */
		off_nl_nosnap = 3;	/* 802.2 */
		return;

	case DLT_RAW:
	case DLT_IPV4:
	case DLT_IPV6:
		off_linktype = -1;
		off_macpl = 0;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_LINUX_SLL:	/* fake header for Linux cooked socket */
		off_linktype = 14;
		off_macpl = 16;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_LTALK:
		/*
		 * LocalTalk does have a 1-byte type field in the LLAP header,
		 * but really it just indicates whether there is a "short" or
		 * "long" DDP packet following.
		 */
		off_linktype = -1;
		off_macpl = 0;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_IP_OVER_FC:
		/*
		 * RFC 2625 IP-over-Fibre-Channel doesn't really have a
		 * link-level type field.  We set "off_linktype" to the
		 * offset of the LLC header.
		 *
		 * To check for Ethernet types, we assume that SSAP = SNAP
		 * is being used and pick out the encapsulated Ethernet type.
		 * XXX - should we generate code to check for SNAP? RFC
		 * 2625 says SNAP should be used.
		 */
		off_linktype = 16;
		off_macpl = 16;
		off_nl = 8;		/* 802.2+SNAP */
		off_nl_nosnap = 3;	/* 802.2 */
		return;

	case DLT_FRELAY:
		/*
		 * XXX - we should set this to handle SNAP-encapsulated
		 * frames (NLPID of 0x80).
		 */
		off_linktype = -1;
		off_macpl = 0;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

                /*
                 * the only BPF-interesting FRF.16 frames are non-control frames;
                 * Frame Relay has a variable length link-layer
                 * so lets start with offset 4 for now and increments later on (FIXME);
                 */
	case DLT_MFR:
		off_linktype = -1;
		off_macpl = 0;
		off_nl = 4;
		off_nl_nosnap = 0;	/* XXX - for now -> no 802.2 LLC */
		return;

	case DLT_APPLE_IP_OVER_IEEE1394:
		off_linktype = 16;
		off_macpl = 18;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;

	case DLT_SYMANTEC_FIREWALL:
		off_linktype = 6;
		off_macpl = 44;
		off_nl = 0;		/* Ethernet II */
		off_nl_nosnap = 0;	/* XXX - what does it do with 802.3 packets? */
		return;

#ifdef HAVE_NET_PFVAR_H
	case DLT_PFLOG:
		off_linktype = 0;
		off_macpl = PFLOG_HDRLEN;
		off_nl = 0;
		off_nl_nosnap = 0;	/* no 802.2 LLC */
		return;
#endif

        case DLT_JUNIPER_MFR:
        case DLT_JUNIPER_MLFR:
        case DLT_JUNIPER_MLPPP:
        case DLT_JUNIPER_PPP:
        case DLT_JUNIPER_CHDLC:
        case DLT_JUNIPER_FRELAY:
                off_linktype = 4;
		off_macpl = 4;
		off_nl = 0;
		off_nl_nosnap = -1;	/* no 802.2 LLC */
                return;

	case DLT_JUNIPER_ATM1:
		off_linktype = 4;	/* in reality variable between 4-8 */
		off_macpl = 4;	/* in reality variable between 4-8 */
		off_nl = 0;
		off_nl_nosnap = 10;
		return;

	case DLT_JUNIPER_ATM2:
		off_linktype = 8;	/* in reality variable between 8-12 */
		off_macpl = 8;	/* in reality variable between 8-12 */
		off_nl = 0;
		off_nl_nosnap = 10;
		return;

		/* frames captured on a Juniper PPPoE service PIC
		 * contain raw ethernet frames */
	case DLT_JUNIPER_PPPOE:
        case DLT_JUNIPER_ETHER:
        	off_macpl = 14;
		off_linktype = 16;
		off_nl = 18;		/* Ethernet II */
		off_nl_nosnap = 21;	/* 802.3+802.2 */
		return;

	case DLT_JUNIPER_PPPOE_ATM:
		off_linktype = 4;
		off_macpl = 6;
		off_nl = 0;
		off_nl_nosnap = -1;	/* no 802.2 LLC */
		return;

	case DLT_JUNIPER_GGSN:
		off_linktype = 6;
		off_macpl = 12;
		off_nl = 0;
		off_nl_nosnap = -1;	/* no 802.2 LLC */
		return;

	case DLT_JUNIPER_ES:
		off_linktype = 6;
		off_macpl = -1;		/* not really a network layer but raw IP addresses */
		off_nl = -1;		/* not really a network layer but raw IP addresses */
		off_nl_nosnap = -1;	/* no 802.2 LLC */
		return;

	case DLT_JUNIPER_MONITOR:
		off_linktype = 12;
		off_macpl = 12;
		off_nl = 0;		/* raw IP/IP6 header */
		off_nl_nosnap = -1;	/* no 802.2 LLC */
		return;

	case DLT_BACNET_MS_TP:
		off_linktype = -1;
		off_macpl = -1;
		off_nl = -1;
		off_nl_nosnap = -1;
		return;

	case DLT_JUNIPER_SERVICES:
		off_linktype = 12;
		off_macpl = -1;		/* L3 proto location dep. on cookie type */
		off_nl = -1;		/* L3 proto location dep. on cookie type */
		off_nl_nosnap = -1;	/* no 802.2 LLC */
		return;

	case DLT_JUNIPER_VP:
		off_linktype = 18;
		off_macpl = -1;
		off_nl = -1;
		off_nl_nosnap = -1;
		return;

	case DLT_JUNIPER_ST:
		off_linktype = 18;
		off_macpl = -1;
		off_nl = -1;
		off_nl_nosnap = -1;
		return;

	case DLT_JUNIPER_ISM:
		off_linktype = 8;
		off_macpl = -1;
		off_nl = -1;
		off_nl_nosnap = -1;
		return;

	case DLT_JUNIPER_VS:
	case DLT_JUNIPER_SRX_E2E:
	case DLT_JUNIPER_FIBRECHANNEL:
	case DLT_JUNIPER_ATM_CEMIC:
		off_linktype = 8;
		off_macpl = -1;
		off_nl = -1;
		off_nl_nosnap = -1;
		return;

	case DLT_MTP2:
		off_li = 2;
		off_li_hsl = 4;
		off_sio = 3;
		off_opc = 4;
		off_dpc = 4;
		off_sls = 7;
		off_linktype = -1;
		off_macpl = -1;
		off_nl = -1;
		off_nl_nosnap = -1;
		return;

	case DLT_MTP2_WITH_PHDR:
		off_li = 6;
		off_li_hsl = 8;
		off_sio = 7;
		off_opc = 8;
		off_dpc = 8;
		off_sls = 11;
		off_linktype = -1;
		off_macpl = -1;
		off_nl = -1;
		off_nl_nosnap = -1;
		return;

	case DLT_ERF:
		off_li = 22;
		off_li_hsl = 24;
		off_sio = 23;
		off_opc = 24;
		off_dpc = 24;
		off_sls = 27;
		off_linktype = -1;
		off_macpl = -1;
		off_nl = -1;
		off_nl_nosnap = -1;
		return;

	case DLT_PFSYNC:
		off_linktype = -1;
		off_macpl = 4;
		off_nl = 0;
		off_nl_nosnap = 0;
		return;

	case DLT_AX25_KISS:
		/*
		 * Currently, only raw "link[N:M]" filtering is supported.
		 */
		off_linktype = -1;	/* variable, min 15, max 71 steps of 7 */
		off_macpl = -1;
		off_nl = -1;		/* variable, min 16, max 71 steps of 7 */
		off_nl_nosnap = -1;	/* no 802.2 LLC */
		off_mac = 1;		/* step over the kiss length byte */
		return;

	case DLT_IPNET:
		off_linktype = 1;
		off_macpl = 24;		/* ipnet header length */
		off_nl = 0;
		off_nl_nosnap = -1;
		return;

	case DLT_NETANALYZER:
		off_mac = 4;		/* MAC header is past 4-byte pseudo-header */
		off_linktype = 16;	/* includes 4-byte pseudo-header */
		off_macpl = 18;		/* pseudo-header+Ethernet header length */
		off_nl = 0;		/* Ethernet II */
		off_nl_nosnap = 3;	/* 802.3+802.2 */
		return;

	case DLT_NETANALYZER_TRANSPARENT:
		off_mac = 12;		/* MAC header is past 4-byte pseudo-header, preamble, and SFD */
		off_linktype = 24;	/* includes 4-byte pseudo-header+preamble+SFD */
		off_macpl = 26;		/* pseudo-header+preamble+SFD+Ethernet header length */
		off_nl = 0;		/* Ethernet II */
		off_nl_nosnap = 3;	/* 802.3+802.2 */
		return;

	default:
		/*
		 * For values in the range in which we've assigned new
		 * DLT_ values, only raw "link[N:M]" filtering is supported.
		 */
		if (linktype >= DLT_MATCHING_MIN &&
		    linktype <= DLT_MATCHING_MAX) {
			off_linktype = -1;
			off_macpl = -1;
			off_nl = -1;
			off_nl_nosnap = -1;
			return;
		}

	}
	bpf_error("unknown data link type %d", linktype);
	/* NOTREACHED */
}

/*
 * Load a value relative to the beginning of the link-layer header.
 * The link-layer header doesn't necessarily begin at the beginning
 * of the packet data; there might be a variable-length prefix containing
 * radio information.
 */
static struct slist *
gen_load_llrel(offset, size)
	u_int offset, size;
{
	struct slist *s, *s2;

	s = gen_llprefixlen();

	/*
	 * If "s" is non-null, it has code to arrange that the X register
	 * contains the length of the prefix preceding the link-layer
	 * header.
	 *
	 * Otherwise, the length of the prefix preceding the link-layer
	 * header is "off_ll".
	 */
	if (s != NULL) {
		/*
		 * There's a variable-length prefix preceding the
		 * link-layer header.  "s" points to a list of statements
		 * that put the length of that prefix into the X register.
		 * do an indirect load, to use the X register as an offset.
		 */
		s2 = new_stmt(BPF_LD|BPF_IND|size);
		s2->s.k = offset;
		sappend(s, s2);
	} else {
		/*
		 * There is no variable-length header preceding the
		 * link-layer header; add in off_ll, which, if there's
		 * a fixed-length header preceding the link-layer header,
		 * is the length of that header.
		 */
		s = new_stmt(BPF_LD|BPF_ABS|size);
		s->s.k = offset + off_ll;
	}
	return s;
}

/*
 * Load a value relative to the beginning of the MAC-layer payload.
 */
static struct slist *
gen_load_macplrel(offset, size)
	u_int offset, size;
{
	struct slist *s, *s2;

	s = gen_off_macpl();

	/*
	 * If s is non-null, the offset of the MAC-layer payload is
	 * variable, and s points to a list of instructions that
	 * arrange that the X register contains that offset.
	 *
	 * Otherwise, the offset of the MAC-layer payload is constant,
	 * and is in off_macpl.
	 */
	if (s != NULL) {
		/*
		 * The offset of the MAC-layer payload is in the X
		 * register.  Do an indirect load, to use the X register
		 * as an offset.
		 */
		s2 = new_stmt(BPF_LD|BPF_IND|size);
		s2->s.k = offset;
		sappend(s, s2);
	} else {
		/*
		 * The offset of the MAC-layer payload is constant,
		 * and is in off_macpl; load the value at that offset
		 * plus the specified offset.
		 */
		s = new_stmt(BPF_LD|BPF_ABS|size);
		s->s.k = off_macpl + offset;
	}
	return s;
}

/*
 * Load a value relative to the beginning of the specified header.
 */
static struct slist *
gen_load_a(offrel, offset, size)
	enum e_offrel offrel;
	u_int offset, size;
{
	struct slist *s, *s2;

	switch (offrel) {

	case OR_PACKET:
                s = new_stmt(BPF_LD|BPF_ABS|size);
                s->s.k = offset;
		break;

	case OR_LINK:
		s = gen_load_llrel(offset, size);
		break;

	case OR_MACPL:
		s = gen_load_macplrel(offset, size);
		break;

	case OR_NET:
		s = gen_load_macplrel(off_nl + offset, size);
		break;

	case OR_NET_NOSNAP:
		s = gen_load_macplrel(off_nl_nosnap + offset, size);
		break;

	case OR_TRAN_IPV4:
		/*
		 * Load the X register with the length of the IPv4 header
		 * (plus the offset of the link-layer header, if it's
		 * preceded by a variable-length header such as a radio
		 * header), in bytes.
		 */
		s = gen_loadx_iphdrlen();

		/*
		 * Load the item at {offset of the MAC-layer payload} +
		 * {offset, relative to the start of the MAC-layer
		 * paylod, of the IPv4 header} + {length of the IPv4 header} +
		 * {specified offset}.
		 *
		 * (If the offset of the MAC-layer payload is variable,
		 * it's included in the value in the X register, and
		 * off_macpl is 0.)
		 */
		s2 = new_stmt(BPF_LD|BPF_IND|size);
		s2->s.k = off_macpl + off_nl + offset;
		sappend(s, s2);
		break;

	case OR_TRAN_IPV6:
		s = gen_load_macplrel(off_nl + 40 + offset, size);
		break;

	default:
		abort();
		return NULL;
	}
	return s;
}

/*
 * Generate code to load into the X register the sum of the length of
 * the IPv4 header and any variable-length header preceding the link-layer
 * header.
 */
static struct slist *
gen_loadx_iphdrlen()
{
	struct slist *s, *s2;

	s = gen_off_macpl();
	if (s != NULL) {
		/*
		 * There's a variable-length prefix preceding the
		 * link-layer header, or the link-layer header is itself
		 * variable-length.  "s" points to a list of statements
		 * that put the offset of the MAC-layer payload into
		 * the X register.
		 *
		 * The 4*([k]&0xf) addressing mode can't be used, as we
		 * don't have a constant offset, so we have to load the
		 * value in question into the A register and add to it
		 * the value from the X register.
		 */
		s2 = new_stmt(BPF_LD|BPF_IND|BPF_B);
		s2->s.k = off_nl;
		sappend(s, s2);
		s2 = new_stmt(BPF_ALU|BPF_AND|BPF_K);
		s2->s.k = 0xf;
		sappend(s, s2);
		s2 = new_stmt(BPF_ALU|BPF_LSH|BPF_K);
		s2->s.k = 2;
		sappend(s, s2);

		/*
		 * The A register now contains the length of the
		 * IP header.  We need to add to it the offset of
		 * the MAC-layer payload, which is still in the X
		 * register, and move the result into the X register.
		 */
		sappend(s, new_stmt(BPF_ALU|BPF_ADD|BPF_X));
		sappend(s, new_stmt(BPF_MISC|BPF_TAX));
	} else {
		/*
		 * There is no variable-length header preceding the
		 * link-layer header, and the link-layer header is
		 * fixed-length; load the length of the IPv4 header,
		 * which is at an offset of off_nl from the beginning
		 * of the MAC-layer payload, and thus at an offset
		 * of off_mac_pl + off_nl from the beginning of the
		 * raw packet data.
		 */
		s = new_stmt(BPF_LDX|BPF_MSH|BPF_B);
		s->s.k = off_macpl + off_nl;
	}
	return s;
}

static struct block *
gen_uncond(rsense)
	int rsense;
{
	struct block *b;
	struct slist *s;

	s = new_stmt(BPF_LD|BPF_IMM);
	s->s.k = !rsense;
	b = new_block(JMP(BPF_JEQ));
	b->stmts = s;

	return b;
}

static inline struct block *
gen_true()
{
	return gen_uncond(1);
}

static inline struct block *
gen_false()
{
	return gen_uncond(0);
}

/*
 * Byte-swap a 32-bit number.
 * ("htonl()" or "ntohl()" won't work - we want to byte-swap even on
 * big-endian platforms.)
 */
#define	SWAPLONG(y) \
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))

/*
 * Generate code to match a particular packet type.
 *
 * "proto" is an Ethernet type value, if > ETHERMTU, or an LLC SAP
 * value, if <= ETHERMTU.  We use that to determine whether to
 * match the type/length field or to check the type/length field for
 * a value <= ETHERMTU to see whether it's a type field and then do
 * the appropriate test.
 */
static struct block *
gen_ether_linktype(proto)
	register int proto;
{
	struct block *b0, *b1;

	switch (proto) {

	case LLCSAP_ISONS:
	case LLCSAP_IP:
	case LLCSAP_NETBEUI:
		/*
		 * OSI protocols and NetBEUI always use 802.2 encapsulation,
		 * so we check the DSAP and SSAP.
		 *
		 * LLCSAP_IP checks for IP-over-802.2, rather
		 * than IP-over-Ethernet or IP-over-SNAP.
		 *
		 * XXX - should we check both the DSAP and the
		 * SSAP, like this, or should we check just the
		 * DSAP, as we do for other types <= ETHERMTU
		 * (i.e., other SAP values)?
		 */
		b0 = gen_cmp_gt(OR_LINK, off_linktype, BPF_H, ETHERMTU);
		gen_not(b0);
		b1 = gen_cmp(OR_MACPL, 0, BPF_H, (bpf_int32)
			     ((proto << 8) | proto));
		gen_and(b0, b1);
		return b1;

	case LLCSAP_IPX:
		/*
		 * Check for;
		 *
		 *	Ethernet_II frames, which are Ethernet
		 *	frames with a frame type of ETHERTYPE_IPX;
		 *
		 *	Ethernet_802.3 frames, which are 802.3
		 *	frames (i.e., the type/length field is
		 *	a length field, <= ETHERMTU, rather than
		 *	a type field) with the first two bytes
		 *	after the Ethernet/802.3 header being
		 *	0xFFFF;
		 *
		 *	Ethernet_802.2 frames, which are 802.3
		 *	frames with an 802.2 LLC header and
		 *	with the IPX LSAP as the DSAP in the LLC
		 *	header;
		 *
		 *	Ethernet_SNAP frames, which are 802.3
		 *	frames with an LLC header and a SNAP
		 *	header and with an OUI of 0x000000
		 *	(encapsulated Ethernet) and a protocol
		 *	ID of ETHERTYPE_IPX in the SNAP header.
		 *
		 * XXX - should we generate the same code both
		 * for tests for LLCSAP_IPX and for ETHERTYPE_IPX?
		 */

		/*
		 * This generates code to check both for the
		 * IPX LSAP (Ethernet_802.2) and for Ethernet_802.3.
		 */
		b0 = gen_cmp(OR_MACPL, 0, BPF_B, (bpf_int32)LLCSAP_IPX);
		b1 = gen_cmp(OR_MACPL, 0, BPF_H, (bpf_int32)0xFFFF);
		gen_or(b0, b1);

		/*
		 * Now we add code to check for SNAP frames with
		 * ETHERTYPE_IPX, i.e. Ethernet_SNAP.
		 */
		b0 = gen_snap(0x000000, ETHERTYPE_IPX);
		gen_or(b0, b1);

		/*
		 * Now we generate code to check for 802.3
		 * frames in general.
		 */
		b0 = gen_cmp_gt(OR_LINK, off_linktype, BPF_H, ETHERMTU);
		gen_not(b0);

		/*
		 * Now add the check for 802.3 frames before the
		 * check for Ethernet_802.2 and Ethernet_802.3,
		 * as those checks should only be done on 802.3
		 * frames, not on Ethernet frames.
		 */
		gen_and(b0, b1);

		/*
		 * Now add the check for Ethernet_II frames, and
		 * do that before checking for the other frame
		 * types.
		 */
		b0 = gen_cmp(OR_LINK, off_linktype, BPF_H,
		    (bpf_int32)ETHERTYPE_IPX);
		gen_or(b0, b1);
		return b1;

	case ETHERTYPE_ATALK:
	case ETHERTYPE_AARP:
		/*
		 * EtherTalk (AppleTalk protocols on Ethernet link
		 * layer) may use 802.2 encapsulation.
		 */

		/*
		 * Check for 802.2 encapsulation (EtherTalk phase 2?);
		 * we check for an Ethernet type field less than
		 * 1500, which means it's an 802.3 length field.
		 */
		b0 = gen_cmp_gt(OR_LINK, off_linktype, BPF_H, ETHERMTU);
		gen_not(b0);

		/*
		 * 802.2-encapsulated ETHERTYPE_ATALK packets are
		 * SNAP packets with an organization code of
		 * 0x080007 (Apple, for Appletalk) and a protocol
		 * type of ETHERTYPE_ATALK (Appletalk).
		 *
		 * 802.2-encapsulated ETHERTYPE_AARP packets are
		 * SNAP packets with an organization code of
		 * 0x000000 (encapsulated Ethernet) and a protocol
		 * type of ETHERTYPE_AARP (Appletalk ARP).
		 */
		if (proto == ETHERTYPE_ATALK)
			b1 = gen_snap(0x080007, ETHERTYPE_ATALK);
		else	/* proto == ETHERTYPE_AARP */
			b1 = gen_snap(0x000000, ETHERTYPE_AARP);
		gen_and(b0, b1);

		/*
		 * Check for Ethernet encapsulation (Ethertalk
		 * phase 1?); we just check for the Ethernet
		 * protocol type.
		 */
		b0 = gen_cmp(OR_LINK, off_linktype, BPF_H, (bpf_int32)proto);

		gen_or(b0, b1);
		return b1;

	default:
		if (proto <= ETHERMTU) {
			/*
			 * This is an LLC SAP value, so the frames
			 * that match would be 802.2 frames.
			 * Check that the frame is an 802.2 frame
			 * (i.e., that the length/type field is
			 * a length field, <= ETHERMTU) and
			 * then check the DSAP.
			 */
			b0 = gen_cmp_gt(OR_LINK, off_linktype, BPF_H, ETHERMTU);
			gen_not(b0);
			b1 = gen_cmp(OR_LINK, off_linktype + 2, BPF_B,
			    (bpf_int32)proto);
			gen_and(b0, b1);
			return b1;
		} else {
			/*
			 * This is an Ethernet type, so compare
			 * the length/type field with it (if
			 * the frame is an 802.2 frame, the length
			 * field will be <= ETHERMTU, and, as
			 * "proto" is > ETHERMTU, this test
			 * will fail and the frame won't match,
			 * which is what we want).
			 */
			return gen_cmp(OR_LINK, off_linktype, BPF_H,
			    (bpf_int32)proto);
		}
	}
}

/*
 * "proto" is an Ethernet type value and for IPNET, if it is not IPv4
 * or IPv6 then we have an error.
 */
static struct block *
gen_ipnet_linktype(proto)
	register int proto;
{
	switch (proto) {

	case ETHERTYPE_IP:
		return gen_cmp(OR_LINK, off_linktype, BPF_B,
		    (bpf_int32)IPH_AF_INET);
		/* NOTREACHED */

	case ETHERTYPE_IPV6:
		return gen_cmp(OR_LINK, off_linktype, BPF_B,
		    (bpf_int32)IPH_AF_INET6);
		/* NOTREACHED */

	default:
		break;
	}

	return gen_false();
}

/*
 * Generate code to match a particular packet type.
 *
 * "proto" is an Ethernet type value, if > ETHERMTU, or an LLC SAP
 * value, if <= ETHERMTU.  We use that to determine whether to
 * match the type field or to check the type field for the special
 * LINUX_SLL_P_802_2 value and then do the appropriate test.
 */
static struct block *
gen_linux_sll_linktype(proto)
	register int proto;
{
	struct block *b0, *b1;

	switch (proto) {

	case LLCSAP_ISONS:
	case LLCSAP_IP:
	case LLCSAP_NETBEUI:
		/*
		 * OSI protocols and NetBEUI always use 802.2 encapsulation,
		 * so we check the DSAP and SSAP.
		 *
		 * LLCSAP_IP checks for IP-over-802.2, rather
		 * than IP-over-Ethernet or IP-over-SNAP.
		 *
		 * XXX - should we check both the DSAP and the
		 * SSAP, like this, or should we check just the
		 * DSAP, as we do for other types <= ETHERMTU
		 * (i.e., other SAP values)?
		 */
		b0 = gen_cmp(OR_LINK, off_linktype, BPF_H, LINUX_SLL_P_802_2);
		b1 = gen_cmp(OR_MACPL, 0, BPF_H, (bpf_int32)
			     ((proto << 8) | proto));
		gen_and(b0, b1);
		return b1;

	case LLCSAP_IPX:
		/*
		 *	Ethernet_II frames, which are Ethernet
		 *	frames with a frame type of ETHERTYPE_IPX;
		 *
		 *	Ethernet_802.3 frames, which have a frame
		 *	type of LINUX_SLL_P_802_3;
		 *
		 *	Ethernet_802.2 frames, which are 802.3
		 *	frames with an 802.2 LLC header (i.e, have
		 *	a frame type of LINUX_SLL_P_802_2) and
		 *	with the IPX LSAP as the DSAP in the LLC
		 *	header;
		 *
		 *	Ethernet_SNAP frames, which are 802.3
		 *	frames with an LLC header and a SNAP
		 *	header and with an OUI of 0x000000
		 *	(encapsulated Ethernet) and a protocol
		 *	ID of ETHERTYPE_IPX in the SNAP header.
		 *
		 * First, do the checks on LINUX_SLL_P_802_2
		 * frames; generate the check for either
		 * Ethernet_802.2 or Ethernet_SNAP frames, and
		 * then put a check for LINUX_SLL_P_802_2 frames
		 * before it.
		 */
		b0 = gen_cmp(OR_MACPL, 0, BPF_B, (bpf_int32)LLCSAP_IPX);
		b1 = gen_snap(0x000000, ETHERTYPE_IPX);
		gen_or(b0, b1);
		b0 = gen_cmp(OR_LINK, off_linktype, BPF_H, LINUX_SLL_P_802_2);
		gen_and(b0, b1);

		/*
		 * Now check for 802.3 frames and OR that with
		 * the previous test.
		 */
		b0 = gen_cmp(OR_LINK, off_linktype, BPF_H, LINUX_SLL_P_802_3);
		gen_or(b0, b1);

		/*
		 * Now add the check for Ethernet_II frames, and
		 * do that before checking for the other frame
		 * types.
		 */
		b0 = gen_cmp(OR_LINK, off_linktype, BPF_H,
		    (bpf_int32)ETHERTYPE_IPX);
		gen_or(b0, b1);
		return b1;

	case ETHERTYPE_ATALK:
	case ETHERTYPE_AARP:
		/*
		 * EtherTalk (AppleTalk protocols on Ethernet link
		 * layer) may use 802.2 encapsulation.
		 */

		/*
		 * Check for 802.2 encapsulation (EtherTalk phase 2?);
		 * we check for the 802.2 protocol type in the
		 * "Ethernet type" field.
		 */
		b0 = gen_cmp(OR_LINK, off_linktype, BPF_H, LINUX_SLL_P_802_2);

		/*
		 * 802.2-encapsulated ETHERTYPE_ATALK packets are
		 * SNAP packets with an organization code of
		 * 0x080007 (Apple, for Appletalk) and a protocol
		 * type of ETHERTYPE_ATALK (Appletalk).
		 *
		 * 802.2-encapsulated ETHERTYPE_AARP packets are
		 * SNAP packets with an organization code of
		 * 0x000000 (encapsulated Ethernet) and a protocol
		 * type of ETHERTYPE_AARP (Appletalk ARP).
		 */
		if (proto == ETHERTYPE_ATALK)
			b1 = gen_snap(0x080007, ETHERTYPE_ATALK);
		else	/* proto == ETHERTYPE_AARP */
			b1 = gen_snap(0x000000, ETHERTYPE_AARP);
		gen_and(b0, b1);

		/*
		 * Check for Ethernet encapsulation (Ethertalk
		 * phase 1?); we just check for the Ethernet
		 * protocol type.
		 */
		b0 = gen_cmp(OR_LINK, off_linktype, BPF_H, (bpf_int32)proto);

		gen_or(b0, b1);
		return b1;

	default:
		if (proto <= ETHERMTU) {
			/*
			 * This is an LLC SAP value, so the frames
			 * that match would be 802.2 frames.
			 * Check for the 802.2 protocol type
			 * in the "Ethernet type" field, and
			 * then check the DSAP.
			 */
			b0 = gen_cmp(OR_LINK, off_linktype, BPF_H,
			    LINUX_SLL_P_802_2);
			b1 = gen_cmp(OR_LINK, off_macpl, BPF_B,
			     (bpf_int32)proto);
			gen_and(b0, b1);
			return b1;
		} else {
			/*
			 * This is an Ethernet type, so compare
			 * the length/type field with it (if
			 * the frame is an 802.2 frame, the length
			 * field will be <= ETHERMTU, and, as
			 * "proto" is > ETHERMTU, this test
			 * will fail and the frame won't match,
			 * which is what we want).
			 */
			return gen_cmp(OR_LINK, off_linktype, BPF_H,
			    (bpf_int32)proto);
		}
	}
}

static struct slist *
gen_load_prism_llprefixlen()
{
	struct slist *s1, *s2;
	struct slist *sjeq_avs_cookie;
	struct slist *sjcommon;

	/*
	 * This code is not compatible with the optimizer, as
	 * we are generating jmp instructions within a normal
	 * slist of instructions
	 */
	no_optimize = 1;

	/*
	 * Generate code to load the length of the radio header into
	 * the register assigned to hold that length, if one has been
	 * assigned.  (If one hasn't been assigned, no code we've
	 * generated uses that prefix, so we don't need to generate any
	 * code to load it.)
	 *
	 * Some Linux drivers use ARPHRD_IEEE80211_PRISM but sometimes
	 * or always use the AVS header rather than the Prism header.
	 * We load a 4-byte big-endian value at the beginning of the
	 * raw packet data, and see whether, when masked with 0xFFFFF000,
	 * it's equal to 0x80211000.  If so, that indicates that it's
	 * an AVS header (the masked-out bits are the version number).
	 * Otherwise, it's a Prism header.
	 *
	 * XXX - the Prism header is also, in theory, variable-length,
	 * but no known software generates headers that aren't 144
	 * bytes long.
	 */
	if (reg_off_ll != -1) {
		/*
		 * Load the cookie.
		 */
		s1 = new_stmt(BPF_LD|BPF_W|BPF_ABS);
		s1->s.k = 0;

		/*
		 * AND it with 0xFFFFF000.
		 */
		s2 = new_stmt(BPF_ALU|BPF_AND|BPF_K);
		s2->s.k = 0xFFFFF000;
		sappend(s1, s2);

		/*
		 * Compare with 0x80211000.
		 */
		sjeq_avs_cookie = new_stmt(JMP(BPF_JEQ));
		sjeq_avs_cookie->s.k = 0x80211000;
		sappend(s1, sjeq_avs_cookie);

		/*
		 * If it's AVS:
		 *
		 * The 4 bytes at an offset of 4 from the beginning of
		 * the AVS header are the length of the AVS header.
		 * That field is big-endian.
		 */
		s2 = new_stmt(BPF_LD|BPF_W|BPF_ABS);
		s2->s.k = 4;
		sappend(s1, s2);
		sjeq_avs_cookie->s.jt = s2;

		/*
		 * Now jump to the code to allocate a register
		 * into which to save the header length and
		 * store the length there.  (The "jump always"
		 * instruction needs to have the k field set;
		 * it's added to the PC, so, as we're jumping
		 * over a single instruction, it should be 1.)
		 */
		sjcommon = new_stmt(JMP(BPF_JA));
		sjcommon->s.k = 1;
		sappend(s1, sjcommon);

		/*
		 * Now for the code that handles the Prism header.
		 * Just load the length of the Prism header (144)
		 * into the A register.  Have the test for an AVS
		 * header branch here if we don't have an AVS header.
		 */
		s2 = new_stmt(BPF_LD|BPF_W|BPF_IMM);
		s2->s.k = 144;
		sappend(s1, s2);
		sjeq_avs_cookie->s.jf = s2;

		/*
		 * Now allocate a register to hold that value and store
		 * it.  The code for the AVS header will jump here after
		 * loading the length of the AVS header.
		 */
		s2 = new_stmt(BPF_ST);
		s2->s.k = reg_off_ll;
		sappend(s1, s2);
		sjcommon->s.jf = s2;

		/*
		 * Now move it into the X register.
		 */
		s2 = new_stmt(BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		return (s1);
	} else
		return (NULL);
}

static struct slist *
gen_load_avs_llprefixlen()
{
	struct slist *s1, *s2;

	/*
	 * Generate code to load the length of the AVS header into
	 * the register assigned to hold that length, if one has been
	 * assigned.  (If one hasn't been assigned, no code we've
	 * generated uses that prefix, so we don't need to generate any
	 * code to load it.)
	 */
	if (reg_off_ll != -1) {
		/*
		 * The 4 bytes at an offset of 4 from the beginning of
		 * the AVS header are the length of the AVS header.
		 * That field is big-endian.
		 */
		s1 = new_stmt(BPF_LD|BPF_W|BPF_ABS);
		s1->s.k = 4;

		/*
		 * Now allocate a register to hold that value and store
		 * it.
		 */
		s2 = new_stmt(BPF_ST);
		s2->s.k = reg_off_ll;
		sappend(s1, s2);

		/*
		 * Now move it into the X register.
		 */
		s2 = new_stmt(BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		return (s1);
	} else
		return (NULL);
}

static struct slist *
gen_load_radiotap_llprefixlen()
{
	struct slist *s1, *s2;

	/*
	 * Generate code to load the length of the radiotap header into
	 * the register assigned to hold that length, if one has been
	 * assigned.  (If one hasn't been assigned, no code we've
	 * generated uses that prefix, so we don't need to generate any
	 * code to load it.)
	 */
	if (reg_off_ll != -1) {
		/*
		 * The 2 bytes at offsets of 2 and 3 from the beginning
		 * of the radiotap header are the length of the radiotap
		 * header; unfortunately, it's little-endian, so we have
		 * to load it a byte at a time and construct the value.
		 */

		/*
		 * Load the high-order byte, at an offset of 3, shift it
		 * left a byte, and put the result in the X register.
		 */
		s1 = new_stmt(BPF_LD|BPF_B|BPF_ABS);
		s1->s.k = 3;
		s2 = new_stmt(BPF_ALU|BPF_LSH|BPF_K);
		sappend(s1, s2);
		s2->s.k = 8;
		s2 = new_stmt(BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		/*
		 * Load the next byte, at an offset of 2, and OR the
		 * value from the X register into it.
		 */
		s2 = new_stmt(BPF_LD|BPF_B|BPF_ABS);
		sappend(s1, s2);
		s2->s.k = 2;
		s2 = new_stmt(BPF_ALU|BPF_OR|BPF_X);
		sappend(s1, s2);

		/*
		 * Now allocate a register to hold that value and store
		 * it.
		 */
		s2 = new_stmt(BPF_ST);
		s2->s.k = reg_off_ll;
		sappend(s1, s2);

		/*
		 * Now move it into the X register.
		 */
		s2 = new_stmt(BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		return (s1);
	} else
		return (NULL);
}

/* 
 * At the moment we treat PPI as normal Radiotap encoded
 * packets. The difference is in the function that generates
 * the code at the beginning to compute the header length.
 * Since this code generator of PPI supports bare 802.11
 * encapsulation only (i.e. the encapsulated DLT should be
 * DLT_IEEE802_11) we generate code to check for this too;
 * that's done in finish_parse().
 */
static struct slist *
gen_load_ppi_llprefixlen()
{
	struct slist *s1, *s2;
	
	/*
	 * Generate code to load the length of the radiotap header
	 * into the register assigned to hold that length, if one has
	 * been assigned.
	 */
	if (reg_off_ll != -1) {
		/*
		 * The 2 bytes at offsets of 2 and 3 from the beginning
		 * of the radiotap header are the length of the radiotap
		 * header; unfortunately, it's little-endian, so we have
		 * to load it a byte at a time and construct the value.
		 */

		/*
		 * Load the high-order byte, at an offset of 3, shift it
		 * left a byte, and put the result in the X register.
		 */
		s1 = new_stmt(BPF_LD|BPF_B|BPF_ABS);
		s1->s.k = 3;
		s2 = new_stmt(BPF_ALU|BPF_LSH|BPF_K);
		sappend(s1, s2);
		s2->s.k = 8;
		s2 = new_stmt(BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		/*
		 * Load the next byte, at an offset of 2, and OR the
		 * value from the X register into it.
		 */
		s2 = new_stmt(BPF_LD|BPF_B|BPF_ABS);
		sappend(s1, s2);
		s2->s.k = 2;
		s2 = new_stmt(BPF_ALU|BPF_OR|BPF_X);
		sappend(s1, s2);

		/*
		 * Now allocate a register to hold that value and store
		 * it.
		 */
		s2 = new_stmt(BPF_ST);
		s2->s.k = reg_off_ll;
		sappend(s1, s2);

		/*
		 * Now move it into the X register.
		 */
		s2 = new_stmt(BPF_MISC|BPF_TAX);
		sappend(s1, s2);

		return (s1);
	} else
		return (NULL);
}

/*
 * Load a value relative to the beginning of the link-layer header after the 802.11
 * header, i.e. LLC_SNAP.
 * The link-layer header doesn't necessarily begin at the beginning
 * of the packet data; there might be a variable-length prefix containing
 * radio information.
 */
static struct slist *
gen_load_802_11_header_len(struct slist *s, struct slist *snext)
{
	struct slist *s2;
	struct slist *sjset_data_frame_1;
	struct slist *sjset_data_frame_2;
	struct slist *sjset_qos;
	struct slist *sjset_radiotap_flags;
	struct slist *sjset_radiotap_tsft;
	struct slist *sjset_tsft_datapad, *sjset_notsft_datapad;
	struct slist *s_roundup;

	if (reg_off_macpl == -1) {
		/*
		 * No register has been assigned to the offset of
		 * the MAC-layer payload, which means nobody needs
		 * it; don't bother computing it - just return
		 * what we already have.
		 */
		return (s);
	}

	/*
	 * This code is not compatible with the optimizer, as
	 * we are generating jmp instructions within a normal
	 * slist of instructions
	 */
	no_optimize = 1;
	
	/*
	 * If "s" is non-null, it has code to arrange that the X register
	 * contains the length of the prefix preceding the link-layer
	 * header.
	 *
	 * Otherwise, the length of the prefix preceding the link-layer
	 * header is "off_ll".
	 */
	if (s == NULL) {
		/*
		 * There is no variable-length header preceding the
		 * link-layer header.
		 *
		 * Load the length of the fixed-length prefix preceding
		 * the link-layer header (if any) into the X register,
		 * and store it in the reg_off_macpl register.
		 * That length is off_ll.
		 */
		s = new_stmt(BPF_LDX|BPF_IMM);
		s->s.k = off_ll;
	}

	/*
	 * The X register contains the offset of the beginning of the
	 * link-layer header; add 24, which is the minimum length
	 * of the MAC header for a data frame, to that, and store it
	 * in reg_off_macpl, and then load the Frame Control field,
	 * which is at the offset in the X register, with an indexed load.
	 */
	s2 = new_stmt(BPF_MISC|BPF_TXA);
	sappend(s, s2);
	s2 = new_stmt(BPF_ALU|BPF_ADD|BPF_K);
	s2->s.k = 24;
	sappend(s, s2);
	s2 = new_stmt(BPF_ST);
	s2->s.k = reg_off_macpl;
	sappend(s, s2);

	s2 = new_stmt(BPF_LD|BPF_IND|BPF_B);
	s2->s.k = 0;
	sappend(s, s2);

	/*
	 * Check the Frame Control field to see if this is a data frame;
	 * a data frame has the 0x08 bit (b3) in that field set and the
	 * 0x04 bit (b2) clear.
	 */
	sjset_data_frame_1 = new_stmt(JMP(BPF_JSET));
	sjset_data_frame_1->s.k = 0x08;
	sappend(s, sjset_data_frame_1);
		
	/*
	 * If b3 is set, test b2, otherwise go to the first statement of
	 * the rest of the program.
	 */
	sjset_data_frame_1->s.jt = sjset_data_frame_2 = new_stmt(JMP(BPF_JSET));
	sjset_data_frame_2->s.k = 0x04;
	sappend(s, sjset_data_frame_2);
	sjset_data_frame_1->s.jf = snext;

	/*
	 * If b2 is not set, this is a data frame; test the QoS bit.
	 * Otherwise, go to the first statement of the rest of the
	 * program.
	 */
	sjset_data_frame_2->s.jt = snext;
	sjset_data_frame_2->s.jf = sjset_qos = new_stmt(JMP(BPF_JSET));
	sjset_qos->s.k = 0x80;	/* QoS bit */
	sappend(s, sjset_qos);
		
	/*
	 * If it's set, add 2 to reg_off_macpl, to skip the QoS
	 * field.
	 * Otherwise, go to the first statement of the rest of the
	 * program.
	 */
	sjset_qos->s.jt = s2 = new_stmt(BPF_LD|BPF_MEM);
	s2->s.k = reg_off_macpl;
	sappend(s, s2);
	s2 = new_stmt(BPF_ALU|BPF_ADD|BPF_IMM);
	s2->s.k = 2;
	sappend(s, s2);
	s2 = new_stmt(BPF_ST);
	s2->s.k = reg_off_macpl;
	sappend(s, s2);

	/*
	 * If we have a radiotap header, look at it to see whether
	 * there's Atheros padding between the MAC-layer header
	 * and the payload.
	 *
	 * Note: all of the fields in the radiotap header are
	 * little-endian, so we byte-swap all of the values
	 * we test against, as they will be loaded as big-endian
	 * values.
	 */
	if (linktype == DLT_IEEE802_11_RADIO) {
		/*
		 * Is the IEEE80211_RADIOTAP_FLAGS bit (0x0000002) set
		 * in the presence flag?
		 */
		sjset_qos->s.jf = s2 = new_stmt(BPF_LD|BPF_ABS|BPF_W);
		s2->s.k = 4;
		sappend(s, s2);

		sjset_radiotap_flags = new_stmt(JMP(BPF_JSET));
		sjset_radiotap_flags->s.k = SWAPLONG(0x00000002);
		sappend(s, sjset_radiotap_flags);

		/*
		 * If not, skip all of this.
		 */
		sjset_radiotap_flags->s.jf = snext;

		/*
		 * Otherwise, is the IEEE80211_RADIOTAP_TSFT bit set?
		 */
		sjset_radiotap_tsft = sjset_radiotap_flags->s.jt =
		    new_stmt(JMP(BPF_JSET));
		sjset_radiotap_tsft->s.k = SWAPLONG(0x00000001);
		sappend(s, sjset_radiotap_tsft);

		/*
		 * If IEEE80211_RADIOTAP_TSFT is set, the flags field is
		 * at an offset of 16 from the beginning of the raw packet
		 * data (8 bytes for the radiotap header and 8 bytes for
		 * the TSFT field).
		 *
		 * Test whether the IEEE80211_RADIOTAP_F_DATAPAD bit (0x20)
		 * is set.
		 */
		sjset_radiotap_tsft->s.jt = s2 = new_stmt(BPF_LD|BPF_ABS|BPF_B);
		s2->s.k = 16;
		sappend(s, s2);

		sjset_tsft_datapad = new_stmt(JMP(BPF_JSET));
		sjset_tsft_datapad->s.k = 0x20;
		sappend(s, sjset_tsft_datapad);

		/*
		 * If IEEE80211_RADIOTAP_TSFT is not set, the flags field is
		 * at an offset of 8 from the beginning of the raw packet
		 * data (8 bytes for the radiotap header).
		 *
		 * Test whether the IEEE80211_RADIOTAP_F_DATAPAD bit (0x20)
		 * is set.
		 */
		sjset_radiotap_tsft->s.jf = s2 = new_stmt(BPF_LD|BPF_ABS|BPF_B);
		s2->s.k = 8;
		sappend(s, s2);

		sjset_notsft_datapad = new_stmt(JMP(BPF_JSET));
		sjset_notsft_datapad->s.k = 0x20;
		sappend(s, sjset_notsft_datapad);

		/*
		 * In either case, if IEEE80211_RADIOTAP_F_DATAPAD is
		 * set, round the length of the 802.11 header to
		 * a multiple of 4.  Do that by adding 3 and then
		 * dividing by and multiplying by 4, which we do by
		 * ANDing with ~3.
		 */
		s_roundup = new_stmt(BPF_LD|BPF_MEM);
		s_roundup->s.k = reg_off_macpl;
		sappend(s, s_roundup);
		s2 = new_stmt(BPF_ALU|BPF_ADD|BPF_IMM);
		s2->s.k = 3;
		sappend(s, s2);
		s2 = new_stmt(BPF_ALU|BPF_AND|BPF_IMM);
		s2->s.k = ~3;
		sappend(s, s2);
		s2 = new_stmt(BPF_ST);
		s2->s.k = reg_off_macpl;
		sappend(s, s2);

		sjset_tsft_datapad->s.jt = s_roundup;
		sjset_tsft_datapad->s.jf = snext;
		sjset_notsft_datapad->s.jt = s_roundup;
		sjset_notsft_datapad->s.jf = snext;
	} else
		sjset_qos->s.jf = snext;

	return s;
}

static void
insert_compute_vloffsets(b)
	struct block *b;
{
	struct slist *s;

	/*
	 * For link-layer types that have a variable-length header
	 * preceding the link-layer header, generate code to load
	 * the offset of the link-layer header into the register
	 * assigned to that offset, if any.
	 */
	switch (linktype) {

	case DLT_PRISM_HEADER:
		s = gen_load_prism_llprefixlen();
		break;

	case DLT_IEEE802_11_RADIO_AVS:
		s = gen_load_avs_llprefixlen();
		break;

	case DLT_IEEE802_11_RADIO:
		s = gen_load_radiotap_llprefixlen();
		break;

	case DLT_PPI:
		s = gen_load_ppi_llprefixlen();
		break;

	default:
		s = NULL;
		break;
	}

	/*
	 * For link-layer types that have a variable-length link-layer
	 * header, generate code to load the offset of the MAC-layer
	 * payload into the register assigned to that offset, if any.
	 */
	switch (linktype) {

	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
	case DLT_PPI:
		s = gen_load_802_11_header_len(s, b->stmts);
		break;
	}

	/*
	 * If we have any offset-loading code, append all the
	 * existing statements in the block to those statements,
	 * and make the resulting list the list of statements
	 * for the block.
	 */
	if (s != NULL) {
		sappend(s, b->stmts);
		b->stmts = s;
	}
}

static struct block *
gen_ppi_dlt_check(void)
{
	struct slist *s_load_dlt;
	struct block *b;

	if (linktype == DLT_PPI)
	{
		/* Create the statements that check for the DLT
		 */
		s_load_dlt = new_stmt(BPF_LD|BPF_W|BPF_ABS);
		s_load_dlt->s.k = 4;

		b = new_block(JMP(BPF_JEQ));

		b->stmts = s_load_dlt;
		b->s.k = SWAPLONG(DLT_IEEE802_11);
	}
	else
	{
		b = NULL;
	}

	return b;
}

static struct slist *
gen_prism_llprefixlen(void)
{
	struct slist *s;

	if (reg_off_ll == -1) {
		/*
		 * We haven't yet assigned a register for the length
		 * of the radio header; allocate one.
		 */
		reg_off_ll = alloc_reg();
	}

	/*
	 * Load the register containing the radio length
	 * into the X register.
	 */
	s = new_stmt(BPF_LDX|BPF_MEM);
	s->s.k = reg_off_ll;
	return s;
}

static struct slist *
gen_avs_llprefixlen(void)
{
	struct slist *s;

	if (reg_off_ll == -1) {
		/*
		 * We haven't yet assigned a register for the length
		 * of the AVS header; allocate one.
		 */
		reg_off_ll = alloc_reg();
	}

	/*
	 * Load the register containing the AVS length
	 * into the X register.
	 */
	s = new_stmt(BPF_LDX|BPF_MEM);
	s->s.k = reg_off_ll;
	return s;
}

static struct slist *
gen_radiotap_llprefixlen(void)
{
	struct slist *s;

	if (reg_off_ll == -1) {
		/*
		 * We haven't yet assigned a register for the length
		 * of the radiotap header; allocate one.
		 */
		reg_off_ll = alloc_reg();
	}

	/*
	 * Load the register containing the radiotap length
	 * into the X register.
	 */
	s = new_stmt(BPF_LDX|BPF_MEM);
	s->s.k = reg_off_ll;
	return s;
}

/* 
 * At the moment we treat PPI as normal Radiotap encoded
 * packets. The difference is in the function that generates
 * the code at the beginning to compute the header length.
 * Since this code generator of PPI supports bare 802.11
 * encapsulation only (i.e. the encapsulated DLT should be
 * DLT_IEEE802_11) we generate code to check for this too.
 */
static struct slist *
gen_ppi_llprefixlen(void)
{
	struct slist *s;

	if (reg_off_ll == -1) {
		/*
		 * We haven't yet assigned a register for the length
		 * of the radiotap header; allocate one.
		 */
		reg_off_ll = alloc_reg();
	}

	/*
	 * Load the register containing the PPI length
	 * into the X register.
	 */
	s = new_stmt(BPF_LDX|BPF_MEM);
	s->s.k = reg_off_ll;
	return s;
}

/*
 * Generate code to compute the link-layer header length, if necessary,
 * putting it into the X register, and to return either a pointer to a
 * "struct slist" for the list of statements in that code, or NULL if
 * no code is necessary.
 */
static struct slist *
gen_llprefixlen(void)
{
	switch (linktype) {

	case DLT_PRISM_HEADER:
		return gen_prism_llprefixlen();

	case DLT_IEEE802_11_RADIO_AVS:
		return gen_avs_llprefixlen();

	case DLT_IEEE802_11_RADIO:
		return gen_radiotap_llprefixlen();

	case DLT_PPI:
		return gen_ppi_llprefixlen();

	default:
		return NULL;
	}
}

/*
 * Generate code to load the register containing the offset of the
 * MAC-layer payload into the X register; if no register for that offset
 * has been allocated, allocate it first.
 */
static struct slist *
gen_off_macpl(void)
{
	struct slist *s;

	if (off_macpl_is_variable) {
		if (reg_off_macpl == -1) {
			/*
			 * We haven't yet assigned a register for the offset
			 * of the MAC-layer payload; allocate one.
			 */
			reg_off_macpl = alloc_reg();
		}

		/*
		 * Load the register containing the offset of the MAC-layer
		 * payload into the X register.
		 */
		s = new_stmt(BPF_LDX|BPF_MEM);
		s->s.k = reg_off_macpl;
		return s;
	} else {
		/*
		 * That offset isn't variable, so we don't need to
		 * generate any code.
		 */
		return NULL;
	}
}

/*
 * Map an Ethernet type to the equivalent PPP type.
 */
static int
ethertype_to_ppptype(proto)
	int proto;
{
	switch (proto) {

	case ETHERTYPE_IP:
		proto = PPP_IP;
		break;

	case ETHERTYPE_IPV6:
		proto = PPP_IPV6;
		break;

	case ETHERTYPE_DN:
		proto = PPP_DECNET;
		break;

	case ETHERTYPE_ATALK:
		proto = PPP_APPLE;
		break;

	case ETHERTYPE_NS:
		proto = PPP_NS;
		break;

	case LLCSAP_ISONS:
		proto = PPP_OSI;
		break;

	case LLCSAP_8021D:
		/*
		 * I'm assuming the "Bridging PDU"s that go
		 * over PPP are Spanning Tree Protocol
		 * Bridging PDUs.
		 */
		proto = PPP_BRPDU;
		break;

	case LLCSAP_IPX:
		proto = PPP_IPX;
		break;
	}
	return (proto);
}

/*
 * Generate code to match a particular packet type by matching the
 * link-layer type field or fields in the 802.2 LLC header.
 *
 * "proto" is an Ethernet type value, if > ETHERMTU, or an LLC SAP
 * value, if <= ETHERMTU.
 */
static struct block *
gen_linktype(proto)
	register int proto;
{
	struct block *b0, *b1, *b2;

	/* are we checking MPLS-encapsulated packets? */
	if (label_stack_depth > 0) {
		switch (proto) {
		case ETHERTYPE_IP:
		case PPP_IP:
			/* FIXME add other L3 proto IDs */
			return gen_mpls_linktype(Q_IP); 

		case ETHERTYPE_IPV6:
		case PPP_IPV6:
			/* FIXME add other L3 proto IDs */
			return gen_mpls_linktype(Q_IPV6); 

		default:
			bpf_error("unsupported protocol over mpls");
			/* NOTREACHED */
		}
	}

	/*
	 * Are we testing PPPoE packets?
	 */
	if (is_pppoes) {
		/*
		 * The PPPoE session header is part of the
		 * MAC-layer payload, so all references
		 * should be relative to the beginning of
		 * that payload.
		 */

		/*
		 * We use Ethernet protocol types inside libpcap;
		 * map them to the corresponding PPP protocol types.
		 */
		proto = ethertype_to_ppptype(proto);
		return gen_cmp(OR_MACPL, off_linktype, BPF_H, (bpf_int32)proto);
	}

	switch (linktype) {

	case DLT_EN10MB:
	case DLT_NETANALYZER:
	case DLT_NETANALYZER_TRANSPARENT:
		return gen_ether_linktype(proto);
		/*NOTREACHED*/
		break;

	case DLT_C_HDLC:
		switch (proto) {

		case LLCSAP_ISONS:
			proto = (proto << 8 | LLCSAP_ISONS);
			/* fall through */

		default:
			return gen_cmp(OR_LINK, off_linktype, BPF_H,
			    (bpf_int32)proto);
			/*NOTREACHED*/
			break;
		}
		break;

	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
	case DLT_PPI:
		/*
		 * Check that we have a data frame.
		 */
		b0 = gen_check_802_11_data_frame();

		/*
		 * Now check for the specified link-layer type.
		 */
		b1 = gen_llc_linktype(proto);
		gen_and(b0, b1);
		return b1;
		/*NOTREACHED*/
		break;

	case DLT_FDDI:
		/*
		 * XXX - check for asynchronous frames, as per RFC 1103.
		 */
		return gen_llc_linktype(proto);
		/*NOTREACHED*/
		break;

	case DLT_IEEE802:
		/*
		 * XXX - check for LLC PDUs, as per IEEE 802.5.
		 */
		return gen_llc_linktype(proto);
		/*NOTREACHED*/
		break;

	case DLT_ATM_RFC1483:
	case DLT_ATM_CLIP:
	case DLT_IP_OVER_FC:
		return gen_llc_linktype(proto);
		/*NOTREACHED*/
		break;

	case DLT_SUNATM:
		/*
		 * If "is_lane" is set, check for a LANE-encapsulated
		 * version of this protocol, otherwise check for an
		 * LLC-encapsulated version of this protocol.
		 *
		 * We assume LANE means Ethernet, not Token Ring.
		 */
		if (is_lane) {
			/*
			 * Check that the packet doesn't begin with an
			 * LE Control marker.  (We've already generated
			 * a test for LANE.)
			 */
			b0 = gen_cmp(OR_LINK, SUNATM_PKT_BEGIN_POS, BPF_H,
			    0xFF00);
			gen_not(b0);

			/*
			 * Now generate an Ethernet test.
			 */
			b1 = gen_ether_linktype(proto);
			gen_and(b0, b1);
			return b1;
		} else {
			/*
			 * Check for LLC encapsulation and then check the
			 * protocol.
			 */
			b0 = gen_atmfield_code(A_PROTOTYPE, PT_LLC, BPF_JEQ, 0);
			b1 = gen_llc_linktype(proto);
			gen_and(b0, b1);
			return b1;
		}
		/*NOTREACHED*/
		break;

	case DLT_LINUX_SLL:
		return gen_linux_sll_linktype(proto);
		/*NOTREACHED*/
		break;

	case DLT_SLIP:
	case DLT_SLIP_BSDOS:
	case DLT_RAW:
		/*
		 * These types don't provide any type field; packets
		 * are always IPv4 or IPv6.
		 *
		 * XXX - for IPv4, check for a version number of 4, and,
		 * for IPv6, check for a version number of 6?
		 */
		switch (proto) {

		case ETHERTYPE_IP:
			/* Check for a version number of 4. */
			return gen_mcmp(OR_LINK, 0, BPF_B, 0x40, 0xF0);

		case ETHERTYPE_IPV6:
			/* Check for a version number of 6. */
			return gen_mcmp(OR_LINK, 0, BPF_B, 0x60, 0xF0);

		default:
			return gen_false();		/* always false */
		}
		/*NOTREACHED*/
		break;

	case DLT_IPV4:
		/*
		 * Raw IPv4, so no type field.
		 */
		if (proto == ETHERTYPE_IP)
			return gen_true();		/* always true */

		/* Checking for something other than IPv4; always false */
		return gen_false();
		/*NOTREACHED*/
		break;

	case DLT_IPV6:
		/*
		 * Raw IPv6, so no type field.
		 */
		if (proto == ETHERTYPE_IPV6)
			return gen_true();		/* always true */

		/* Checking for something other than IPv6; always false */
		return gen_false();
		/*NOTREACHED*/
		break;

	case DLT_PPP:
	case DLT_PPP_PPPD:
	case DLT_PPP_SERIAL:
	case DLT_PPP_ETHER:
		/*
		 * We use Ethernet protocol types inside libpcap;
		 * map them to the corresponding PPP protocol types.
		 */
		proto = ethertype_to_ppptype(proto);
		return gen_cmp(OR_LINK, off_linktype, BPF_H, (bpf_int32)proto);
		/*NOTREACHED*/
		break;

	case DLT_PPP_BSDOS:
		/*
		 * We use Ethernet protocol types inside libpcap;
		 * map them to the corresponding PPP protocol types.
		 */
		switch (proto) {

		case ETHERTYPE_IP:
			/*
			 * Also check for Van Jacobson-compressed IP.
			 * XXX - do this for other forms of PPP?
			 */
			b0 = gen_cmp(OR_LINK, off_linktype, BPF_H, PPP_IP);
			b1 = gen_cmp(OR_LINK, off_linktype, BPF_H, PPP_VJC);
			gen_or(b0, b1);
			b0 = gen_cmp(OR_LINK, off_linktype, BPF_H, PPP_VJNC);
			gen_or(b1, b0);
			return b0;

		default:
			proto = ethertype_to_ppptype(proto);
			return gen_cmp(OR_LINK, off_linktype, BPF_H,
				(bpf_int32)proto);
		}
		/*NOTREACHED*/
		break;

	case DLT_NULL:
	case DLT_LOOP:
	case DLT_ENC:
		/*
		 * For DLT_NULL, the link-layer header is a 32-bit
		 * word containing an AF_ value in *host* byte order,
		 * and for DLT_ENC, the link-layer header begins
		 * with a 32-bit work containing an AF_ value in
		 * host byte order.
		 *
		 * In addition, if we're reading a saved capture file,
		 * the host byte order in the capture may not be the
		 * same as the host byte order on this machine.
		 *
		 * For DLT_LOOP, the link-layer header is a 32-bit
		 * word containing an AF_ value in *network* byte order.
		 *
		 * XXX - AF_ values may, unfortunately, be platform-
		 * dependent; for example, FreeBSD's AF_INET6 is 24
		 * whilst NetBSD's and OpenBSD's is 26.
		 *
		 * This means that, when reading a capture file, just
		 * checking for our AF_INET6 value won't work if the
		 * capture file came from another OS.
		 */
		switch (proto) {

		case ETHERTYPE_IP:
			proto = AF_INET;
			break;

#ifdef INET6
		case ETHERTYPE_IPV6:
			proto = AF_INET6;
			break;
#endif

		default:
			/*
			 * Not a type on which we support filtering.
			 * XXX - support those that have AF_ values
			 * #defined on this platform, at least?
			 */
			return gen_false();
		}

		if (linktype == DLT_NULL || linktype == DLT_ENC) {
			/*
			 * The AF_ value is in host byte order, but
			 * the BPF interpreter will convert it to
			 * network byte order.
			 *
			 * If this is a save file, and it's from a
			 * machine with the opposite byte order to
			 * ours, we byte-swap the AF_ value.
			 *
			 * Then we run it through "htonl()", and
			 * generate code to compare against the result.
			 */
			if (bpf_pcap->rfile != NULL && bpf_pcap->swapped)
				proto = SWAPLONG(proto);
			proto = htonl(proto);
		}
		return (gen_cmp(OR_LINK, 0, BPF_W, (bpf_int32)proto));

#ifdef HAVE_NET_PFVAR_H
	case DLT_PFLOG:
		/*
		 * af field is host byte order in contrast to the rest of
		 * the packet.
		 */
		if (proto == ETHERTYPE_IP)
			return (gen_cmp(OR_LINK, offsetof(struct pfloghdr, af),
			    BPF_B, (bpf_int32)AF_INET));
		else if (proto == ETHERTYPE_IPV6)
			return (gen_cmp(OR_LINK, offsetof(struct pfloghdr, af),
			    BPF_B, (bpf_int32)AF_INET6));
		else
			return gen_false();
		/*NOTREACHED*/
		break;
#endif /* HAVE_NET_PFVAR_H */

	case DLT_ARCNET:
	case DLT_ARCNET_LINUX:
		/*
		 * XXX should we check for first fragment if the protocol
		 * uses PHDS?
		 */
		switch (proto) {

		default:
			return gen_false();

		case ETHERTYPE_IPV6:
			return (gen_cmp(OR_LINK, off_linktype, BPF_B,
				(bpf_int32)ARCTYPE_INET6));

		case ETHERTYPE_IP:
			b0 = gen_cmp(OR_LINK, off_linktype, BPF_B,
				     (bpf_int32)ARCTYPE_IP);
			b1 = gen_cmp(OR_LINK, off_linktype, BPF_B,
				     (bpf_int32)ARCTYPE_IP_OLD);
			gen_or(b0, b1);
			return (b1);

		case ETHERTYPE_ARP:
			b0 = gen_cmp(OR_LINK, off_linktype, BPF_B,
				     (bpf_int32)ARCTYPE_ARP);
			b1 = gen_cmp(OR_LINK, off_linktype, BPF_B,
				     (bpf_int32)ARCTYPE_ARP_OLD);
			gen_or(b0, b1);
			return (b1);

		case ETHERTYPE_REVARP:
			return (gen_cmp(OR_LINK, off_linktype, BPF_B,
					(bpf_int32)ARCTYPE_REVARP));

		case ETHERTYPE_ATALK:
			return (gen_cmp(OR_LINK, off_linktype, BPF_B,
					(bpf_int32)ARCTYPE_ATALK));
		}
		/*NOTREACHED*/
		break;

	case DLT_LTALK:
		switch (proto) {
		case ETHERTYPE_ATALK:
			return gen_true();
		default:
			return gen_false();
		}
		/*NOTREACHED*/
		break;

	case DLT_FRELAY:
		/*
		 * XXX - assumes a 2-byte Frame Relay header with
		 * DLCI and flags.  What if the address is longer?
		 */
		switch (proto) {

		case ETHERTYPE_IP:
			/*
			 * Check for the special NLPID for IP.
			 */
			return gen_cmp(OR_LINK, 2, BPF_H, (0x03<<8) | 0xcc);

		case ETHERTYPE_IPV6:
			/*
			 * Check for the special NLPID for IPv6.
			 */
			return gen_cmp(OR_LINK, 2, BPF_H, (0x03<<8) | 0x8e);

		case LLCSAP_ISONS:
			/*
			 * Check for several OSI protocols.
			 *
			 * Frame Relay packets typically have an OSI
			 * NLPID at the beginning; we check for each
			 * of them.
			 *
			 * What we check for is the NLPID and a frame
			 * control field of UI, i.e. 0x03 followed
			 * by the NLPID.
			 */
			b0 = gen_cmp(OR_LINK, 2, BPF_H, (0x03<<8) | ISO8473_CLNP);
			b1 = gen_cmp(OR_LINK, 2, BPF_H, (0x03<<8) | ISO9542_ESIS);
			b2 = gen_cmp(OR_LINK, 2, BPF_H, (0x03<<8) | ISO10589_ISIS);
			gen_or(b1, b2);
			gen_or(b0, b2);
			return b2;

		default:
			return gen_false();
		}
		/*NOTREACHED*/
		break;

	case DLT_MFR:
		bpf_error("Multi-link Frame Relay link-layer type filtering not implemented");

        case DLT_JUNIPER_MFR:
        case DLT_JUNIPER_MLFR:
        case DLT_JUNIPER_MLPPP:
	case DLT_JUNIPER_ATM1:
	case DLT_JUNIPER_ATM2:
	case DLT_JUNIPER_PPPOE:
	case DLT_JUNIPER_PPPOE_ATM:
        case DLT_JUNIPER_GGSN:
        case DLT_JUNIPER_ES:
        case DLT_JUNIPER_MONITOR:
        case DLT_JUNIPER_SERVICES:
        case DLT_JUNIPER_ETHER:
        case DLT_JUNIPER_PPP:
        case DLT_JUNIPER_FRELAY:
        case DLT_JUNIPER_CHDLC:
        case DLT_JUNIPER_VP:
        case DLT_JUNIPER_ST:
        case DLT_JUNIPER_ISM:
        case DLT_JUNIPER_VS:
        case DLT_JUNIPER_SRX_E2E:
        case DLT_JUNIPER_FIBRECHANNEL:
	case DLT_JUNIPER_ATM_CEMIC:

		/* just lets verify the magic number for now -
		 * on ATM we may have up to 6 different encapsulations on the wire
		 * and need a lot of heuristics to figure out that the payload
		 * might be;
		 *
		 * FIXME encapsulation specific BPF_ filters
		 */
		return gen_mcmp(OR_LINK, 0, BPF_W, 0x4d474300, 0xffffff00); /* compare the magic number */

	case DLT_BACNET_MS_TP:
		return gen_mcmp(OR_LINK, 0, BPF_W, 0x55FF0000, 0xffff0000);

	case DLT_IPNET:
		return gen_ipnet_linktype(proto);

	case DLT_LINUX_IRDA:
		bpf_error("IrDA link-layer type filtering not implemented");

	case DLT_DOCSIS:
		bpf_error("DOCSIS link-layer type filtering not implemented");

	case DLT_MTP2:
	case DLT_MTP2_WITH_PHDR:
		bpf_error("MTP2 link-layer type filtering not implemented");

	case DLT_ERF:
		bpf_error("ERF link-layer type filtering not implemented");

	case DLT_PFSYNC:
		bpf_error("PFSYNC link-layer type filtering not implemented");

	case DLT_LINUX_LAPD:
		bpf_error("LAPD link-layer type filtering not implemented");

	case DLT_USB:
	case DLT_USB_LINUX:
	case DLT_USB_LINUX_MMAPPED:
		bpf_error("USB link-layer type filtering not implemented");

	case DLT_BLUETOOTH_HCI_H4:
	case DLT_BLUETOOTH_HCI_H4_WITH_PHDR:
		bpf_error("Bluetooth link-layer type filtering not implemented");

	case DLT_CAN20B:
	case DLT_CAN_SOCKETCAN:
		bpf_error("CAN link-layer type filtering not implemented");

	case DLT_IEEE802_15_4:
	case DLT_IEEE802_15_4_LINUX:
	case DLT_IEEE802_15_4_NONASK_PHY:
	case DLT_IEEE802_15_4_NOFCS:
		bpf_error("IEEE 802.15.4 link-layer type filtering not implemented");

	case DLT_IEEE802_16_MAC_CPS_RADIO:
		bpf_error("IEEE 802.16 link-layer type filtering not implemented");

	case DLT_SITA:
		bpf_error("SITA link-layer type filtering not implemented");

	case DLT_RAIF1:
		bpf_error("RAIF1 link-layer type filtering not implemented");

	case DLT_IPMB:
		bpf_error("IPMB link-layer type filtering not implemented");

	case DLT_AX25_KISS:
		bpf_error("AX.25 link-layer type filtering not implemented");
	}

	/*
	 * All the types that have no encapsulation should either be
	 * handled as DLT_SLIP, DLT_SLIP_BSDOS, and DLT_RAW are, if
	 * all packets are IP packets, or should be handled in some
	 * special case, if none of them are (if some are and some
	 * aren't, the lack of encapsulation is a problem, as we'd
	 * have to find some other way of determining the packet type).
	 *
	 * Therefore, if "off_linktype" is -1, there's an error.
	 */
	if (off_linktype == (u_int)-1)
		abort();

	/*
	 * Any type not handled above should always have an Ethernet
	 * type at an offset of "off_linktype".
	 */
	return gen_cmp(OR_LINK, off_linktype, BPF_H, (bpf_int32)proto);
}

/*
 * Check for an LLC SNAP packet with a given organization code and
 * protocol type; we check the entire contents of the 802.2 LLC and
 * snap headers, checking for DSAP and SSAP of SNAP and a control
 * field of 0x03 in the LLC header, and for the specified organization
 * code and protocol type in the SNAP header.
 */
static struct block *
gen_snap(orgcode, ptype)
	bpf_u_int32 orgcode;
	bpf_u_int32 ptype;
{
	u_char snapblock[8];

	snapblock[0] = LLCSAP_SNAP;	/* DSAP = SNAP */
	snapblock[1] = LLCSAP_SNAP;	/* SSAP = SNAP */
	snapblock[2] = 0x03;		/* control = UI */
	snapblock[3] = (orgcode >> 16);	/* upper 8 bits of organization code */
	snapblock[4] = (orgcode >> 8);	/* middle 8 bits of organization code */
	snapblock[5] = (orgcode >> 0);	/* lower 8 bits of organization code */
	snapblock[6] = (ptype >> 8);	/* upper 8 bits of protocol type */
	snapblock[7] = (ptype >> 0);	/* lower 8 bits of protocol type */
	return gen_bcmp(OR_MACPL, 0, 8, snapblock);
}

/*
 * Generate code to match a particular packet type, for link-layer types
 * using 802.2 LLC headers.
 *
 * This is *NOT* used for Ethernet; "gen_ether_linktype()" is used
 * for that - it handles the D/I/X Ethernet vs. 802.3+802.2 issues.
 *
 * "proto" is an Ethernet type value, if > ETHERMTU, or an LLC SAP
 * value, if <= ETHERMTU.  We use that to determine whether to
 * match the DSAP or both DSAP and LSAP or to check the OUI and
 * protocol ID in a SNAP header.
 */
static struct block *
gen_llc_linktype(proto)
	int proto;
{
	/*
	 * XXX - handle token-ring variable-length header.
	 */
	switch (proto) {

	case LLCSAP_IP:
	case LLCSAP_ISONS:
	case LLCSAP_NETBEUI:
		/*
		 * XXX - should we check both the DSAP and the
		 * SSAP, like this, or should we check just the
		 * DSAP, as we do for other types <= ETHERMTU
		 * (i.e., other SAP values)?
		 */
		return gen_cmp(OR_MACPL, 0, BPF_H, (bpf_u_int32)
			     ((proto << 8) | proto));

	case LLCSAP_IPX:
		/*
		 * XXX - are there ever SNAP frames for IPX on
		 * non-Ethernet 802.x networks?
		 */
		return gen_cmp(OR_MACPL, 0, BPF_B,
		    (bpf_int32)LLCSAP_IPX);

	case ETHERTYPE_ATALK:
		/*
		 * 802.2-encapsulated ETHERTYPE_ATALK packets are
		 * SNAP packets with an organization code of
		 * 0x080007 (Apple, for Appletalk) and a protocol
		 * type of ETHERTYPE_ATALK (Appletalk).
		 *
		 * XXX - check for an organization code of
		 * encapsulated Ethernet as well?
		 */
		return gen_snap(0x080007, ETHERTYPE_ATALK);

	default:
		/*
		 * XXX - we don't have to check for IPX 802.3
		 * here, but should we check for the IPX Ethertype?
		 */
		if (proto <= ETHERMTU) {
			/*
			 * This is an LLC SAP value, so check
			 * the DSAP.
			 */
			return gen_cmp(OR_MACPL, 0, BPF_B, (bpf_int32)proto);
		} else {
			/*
			 * This is an Ethernet type; we assume that it's
			 * unlikely that it'll appear in the right place
			 * at random, and therefore check only the
			 * location that would hold the Ethernet type
			 * in a SNAP frame with an organization code of
			 * 0x000000 (encapsulated Ethernet).
			 *
			 * XXX - if we were to check for the SNAP DSAP and
			 * LSAP, as per XXX, and were also to check for an
			 * organization code of 0x000000 (encapsulated
			 * Ethernet), we'd do
			 *
			 *	return gen_snap(0x000000, proto);
			 *
			 * here; for now, we don't, as per the above.
			 * I don't know whether it's worth the extra CPU
			 * time to do the right check or not.
			 */
			return gen_cmp(OR_MACPL, 6, BPF_H, (bpf_int32)proto);
		}
	}
}

static struct block *
gen_hostop(addr, mask, dir, proto, src_off, dst_off)
	bpf_u_int32 addr;
	bpf_u_int32 mask;
	int dir, proto;
	u_int src_off, dst_off;
{
	struct block *b0, *b1;
	u_int offset;

	switch (dir) {

	case Q_SRC:
		offset = src_off;
		break;

	case Q_DST:
		offset = dst_off;
		break;

	case Q_AND:
		b0 = gen_hostop(addr, mask, Q_SRC, proto, src_off, dst_off);
		b1 = gen_hostop(addr, mask, Q_DST, proto, src_off, dst_off);
		gen_and(b0, b1);
		return b1;

	case Q_OR:
	case Q_DEFAULT:
		b0 = gen_hostop(addr, mask, Q_SRC, proto, src_off, dst_off);
		b1 = gen_hostop(addr, mask, Q_DST, proto, src_off, dst_off);
		gen_or(b0, b1);
		return b1;

	default:
		abort();
	}
	b0 = gen_linktype(proto);
	b1 = gen_mcmp(OR_NET, offset, BPF_W, (bpf_int32)addr, mask);
	gen_and(b0, b1);
	return b1;
}

#ifdef INET6
static struct block *
gen_hostop6(addr, mask, dir, proto, src_off, dst_off)
	struct in6_addr *addr;
	struct in6_addr *mask;
	int dir, proto;
	u_int src_off, dst_off;
{
	struct block *b0, *b1;
	u_int offset;
	u_int32_t *a, *m;

	switch (dir) {

	case Q_SRC:
		offset = src_off;
		break;

	case Q_DST:
		offset = dst_off;
		break;

	case Q_AND:
		b0 = gen_hostop6(addr, mask, Q_SRC, proto, src_off, dst_off);
		b1 = gen_hostop6(addr, mask, Q_DST, proto, src_off, dst_off);
		gen_and(b0, b1);
		return b1;

	case Q_OR:
	case Q_DEFAULT:
		b0 = gen_hostop6(addr, mask, Q_SRC, proto, src_off, dst_off);
		b1 = gen_hostop6(addr, mask, Q_DST, proto, src_off, dst_off);
		gen_or(b0, b1);
		return b1;

	default:
		abort();
	}
	/* this order is important */
	a = (u_int32_t *)addr;
	m = (u_int32_t *)mask;
	b1 = gen_mcmp(OR_NET, offset + 12, BPF_W, ntohl(a[3]), ntohl(m[3]));
	b0 = gen_mcmp(OR_NET, offset + 8, BPF_W, ntohl(a[2]), ntohl(m[2]));
	gen_and(b0, b1);
	b0 = gen_mcmp(OR_NET, offset + 4, BPF_W, ntohl(a[1]), ntohl(m[1]));
	gen_and(b0, b1);
	b0 = gen_mcmp(OR_NET, offset + 0, BPF_W, ntohl(a[0]), ntohl(m[0]));
	gen_and(b0, b1);
	b0 = gen_linktype(proto);
	gen_and(b0, b1);
	return b1;
}
#endif

static struct block *
gen_ehostop(eaddr, dir)
	register const u_char *eaddr;
	register int dir;
{
	register struct block *b0, *b1;

	switch (dir) {
	case Q_SRC:
		return gen_bcmp(OR_LINK, off_mac + 6, 6, eaddr);

	case Q_DST:
		return gen_bcmp(OR_LINK, off_mac + 0, 6, eaddr);

	case Q_AND:
		b0 = gen_ehostop(eaddr, Q_SRC);
		b1 = gen_ehostop(eaddr, Q_DST);
		gen_and(b0, b1);
		return b1;

	case Q_DEFAULT:
	case Q_OR:
		b0 = gen_ehostop(eaddr, Q_SRC);
		b1 = gen_ehostop(eaddr, Q_DST);
		gen_or(b0, b1);
		return b1;

	case Q_ADDR1:
		bpf_error("'addr1' is only supported on 802.11 with 802.11 headers");
		break;

	case Q_ADDR2:
		bpf_error("'addr2' is only supported on 802.11 with 802.11 headers");
		break;

	case Q_ADDR3:
		bpf_error("'addr3' is only supported on 802.11 with 802.11 headers");
		break;

	case Q_ADDR4:
		bpf_error("'addr4' is only supported on 802.11 with 802.11 headers");
		break;

	case Q_RA:
		bpf_error("'ra' is only supported on 802.11 with 802.11 headers");
		break;

	case Q_TA:
		bpf_error("'ta' is only supported on 802.11 with 802.11 headers");
		break;
	}
	abort();
	/* NOTREACHED */
}

/*
 * Like gen_ehostop, but for DLT_FDDI
 */
static struct block *
gen_fhostop(eaddr, dir)
	register const u_char *eaddr;
	register int dir;
{
	struct block *b0, *b1;

	switch (dir) {
	case Q_SRC:
		return gen_bcmp(OR_LINK, 6 + 1 + pcap_fddipad, 6, eaddr);

	case Q_DST:
		return gen_bcmp(OR_LINK, 0 + 1 + pcap_fddipad, 6, eaddr);

	case Q_AND:
		b0 = gen_fhostop(eaddr, Q_SRC);
		b1 = gen_fhostop(eaddr, Q_DST);
		gen_and(b0, b1);
		return b1;

	case Q_DEFAULT:
	case Q_OR:
		b0 = gen_fhostop(eaddr, Q_SRC);
		b1 = gen_fhostop(eaddr, Q_DST);
		gen_or(b0, b1);
		return b1;

	case Q_ADDR1:
		bpf_error("'addr1' is only supported on 802.11");
		break;

	case Q_ADDR2:
		bpf_error("'addr2' is only supported on 802.11");
		break;

	case Q_ADDR3:
		bpf_error("'addr3' is only supported on 802.11");
		break;

	case Q_ADDR4:
		bpf_error("'addr4' is only supported on 802.11");
		break;

	case Q_RA:
		bpf_error("'ra' is only supported on 802.11");
		break;

	case Q_TA:
		bpf_error("'ta' is only supported on 802.11");
		break;
	}
	abort();
	/* NOTREACHED */
}

/*
 * Like gen_ehostop, but for DLT_IEEE802 (Token Ring)
 */
static struct block *
gen_thostop(eaddr, dir)
	register const u_char *eaddr;
	register int dir;
{
	register struct block *b0, *b1;

	switch (dir) {
	case Q_SRC:
		return gen_bcmp(OR_LINK, 8, 6, eaddr);

	case Q_DST:
		return gen_bcmp(OR_LINK, 2, 6, eaddr);

	case Q_AND:
		b0 = gen_thostop(eaddr, Q_SRC);
		b1 = gen_thostop(eaddr, Q_DST);
		gen_and(b0, b1);
		return b1;

	case Q_DEFAULT:
	case Q_OR:
		b0 = gen_thostop(eaddr, Q_SRC);
		b1 = gen_thostop(eaddr, Q_DST);
		gen_or(b0, b1);
		return b1;

	case Q_ADDR1:
		bpf_error("'addr1' is only supported on 802.11");
		break;

	case Q_ADDR2:
		bpf_error("'addr2' is only supported on 802.11");
		break;

	case Q_ADDR3:
		bpf_error("'addr3' is only supported on 802.11");
		break;

	case Q_ADDR4:
		bpf_error("'addr4' is only supported on 802.11");
		break;

	case Q_RA:
		bpf_error("'ra' is only supported on 802.11");
		break;

	case Q_TA:
		bpf_error("'ta' is only supported on 802.11");
		break;
	}
	abort();
	/* NOTREACHED */
}

/*
 * Like gen_ehostop, but for DLT_IEEE802_11 (802.11 wireless LAN) and
 * various 802.11 + radio headers.
 */
static struct block *
gen_wlanhostop(eaddr, dir)
	register const u_char *eaddr;
	register int dir;
{
	register struct block *b0, *b1, *b2;
	register struct slist *s;

#ifdef ENABLE_WLAN_FILTERING_PATCH
	/*
	 * TODO GV 20070613
	 * We need to disable the optimizer because the optimizer is buggy
	 * and wipes out some LD instructions generated by the below
	 * code to validate the Frame Control bits
	 */
	no_optimize = 1;
#endif /* ENABLE_WLAN_FILTERING_PATCH */

	switch (dir) {
	case Q_SRC:
		/*
		 * Oh, yuk.
		 *
		 *	For control frames, there is no SA.
		 *
		 *	For management frames, SA is at an
		 *	offset of 10 from the beginning of
		 *	the packet.
		 *
		 *	For data frames, SA is at an offset
		 *	of 10 from the beginning of the packet
		 *	if From DS is clear, at an offset of
		 *	16 from the beginning of the packet
		 *	if From DS is set and To DS is clear,
		 *	and an offset of 24 from the beginning
		 *	of the packet if From DS is set and To DS
		 *	is set.
		 */

		/*
		 * Generate the tests to be done for data frames
		 * with From DS set.
		 *
		 * First, check for To DS set, i.e. check "link[1] & 0x01".
		 */
		s = gen_load_a(OR_LINK, 1, BPF_B);
		b1 = new_block(JMP(BPF_JSET));
		b1->s.k = 0x01;	/* To DS */
		b1->stmts = s;

		/*
		 * If To DS is set, the SA is at 24.
		 */
		b0 = gen_bcmp(OR_LINK, 24, 6, eaddr);
		gen_and(b1, b0);

		/*
		 * Now, check for To DS not set, i.e. check
		 * "!(link[1] & 0x01)".
		 */
		s = gen_load_a(OR_LINK, 1, BPF_B);
		b2 = new_block(JMP(BPF_JSET));
		b2->s.k = 0x01;	/* To DS */
		b2->stmts = s;
		gen_not(b2);

		/*
		 * If To DS is not set, the SA is at 16.
		 */
		b1 = gen_bcmp(OR_LINK, 16, 6, eaddr);
		gen_and(b2, b1);

		/*
		 * Now OR together the last two checks.  That gives
		 * the complete set of checks for data frames with
		 * From DS set.
		 */
		gen_or(b1, b0);

		/*
		 * Now check for From DS being set, and AND that with
		 * the ORed-together checks.
		 */
		s = gen_load_a(OR_LINK, 1, BPF_B);
		b1 = new_block(JMP(BPF_JSET));
		b1->s.k = 0x02;	/* From DS */
		b1->stmts = s;
		gen_and(b1, b0);

		/*
		 * Now check for data frames with From DS not set.
		 */
		s = gen_load_a(OR_LINK, 1, BPF_B);
		b2 = new_block(JMP(BPF_JSET));
		b2->s.k = 0x02;	/* From DS */
		b2->stmts = s;
		gen_not(b2);

		/*
		 * If From DS isn't set, the SA is at 10.
		 */
		b1 = gen_bcmp(OR_LINK, 10, 6, eaddr);
		gen_and(b2, b1);

		/*
		 * Now OR together the checks for data frames with
		 * From DS not set and for data frames with From DS
		 * set; that gives the checks done for data frames.
		 */
		gen_or(b1, b0);

		/*
		 * Now check for a data frame.
		 * I.e, check "link[0] & 0x08".
		 */
		s = gen_load_a(OR_LINK, 0, BPF_B);
		b1 = new_block(JMP(BPF_JSET));
		b1->s.k = 0x08;
		b1->stmts = s;

		/*
		 * AND that with the checks done for data frames.
		 */
		gen_and(b1, b0);

		/*
		 * If the high-order bit of the type value is 0, this
		 * is a management frame.
		 * I.e, check "!(link[0] & 0x08)".
		 */
		s = gen_load_a(OR_LINK, 0, BPF_B);
		b2 = new_block(JMP(BPF_JSET));
		b2->s.k = 0x08;
		b2->stmts = s;
		gen_not(b2);

		/*
		 * For management frames, the SA is at 10.
		 */
		b1 = gen_bcmp(OR_LINK, 10, 6, eaddr);
		gen_and(b2, b1);

		/*
		 * OR that with the checks done for data frames.
		 * That gives the checks done for management and
		 * data frames.
		 */
		gen_or(b1, b0);

		/*
		 * If the low-order bit of the type value is 1,
		 * this is either a control frame or a frame
		 * with a reserved type, and thus not a
		 * frame with an SA.
		 *
		 * I.e., check "!(link[0] & 0x04)".
		 */
		s = gen_load_a(OR_LINK, 0, BPF_B);
		b1 = new_block(JMP(BPF_JSET));
		b1->s.k = 0x04;
		b1->stmts = s;
		gen_not(b1);

		/*
		 * AND that with the checks for data and management
		 * frames.
		 */
		gen_and(b1, b0);
		return b0;

	case Q_DST:
		/*
		 * Oh, yuk.
		 *
		 *	For control frames, there is no DA.
		 *
		 *	For management frames, DA is at an
		 *	offset of 4 from the beginning of
		 *	the packet.
		 *
		 *	For data frames, DA is at an offset
		 *	of 4 from the beginning of the packet
		 *	if To DS is clear and at an offset of
		 *	16 from the beginning of the packet
		 *	if To DS is set.
		 */

		/*
		 * Generate the tests to be done for data frames.
		 *
		 * First, check for To DS set, i.e. "link[1] & 0x01".
		 */
		s = gen_load_a(OR_LINK, 1, BPF_B);
		b1 = new_block(JMP(BPF_JSET));
		b1->s.k = 0x01;	/* To DS */
		b1->stmts = s;

		/*
		 * If To DS is set, the DA is at 16.
		 */
		b0 = gen_bcmp(OR_LINK, 16, 6, eaddr);
		gen_and(b1, b0);

		/*
		 * Now, check for To DS not set, i.e. check
		 * "!(link[1] & 0x01)".
		 */
		s = gen_load_a(OR_LINK, 1, BPF_B);
		b2 = new_block(JMP(BPF_JSET));
		b2->s.k = 0x01;	/* To DS */
		b2->stmts = s;
		gen_not(b2);

		/*
		 * If To DS is not set, the DA is at 4.
		 */
		b1 = gen_bcmp(OR_LINK, 4, 6, eaddr);
		gen_and(b2, b1);

		/*
		 * Now OR together the last two checks.  That gives
		 * the complete set of checks for data frames.
		 */
		gen_or(b1, b0);

		/*
		 * Now check for a data frame.
		 * I.e, check "link[0] & 0x08".
		 */
		s = gen_load_a(OR_LINK, 0, BPF_B);
		b1 = new_block(JMP(BPF_JSET));
		b1->s.k = 0x08;
		b1->stmts = s;

		/*
		 * AND that with the checks done for data frames.
		 */
		gen_and(b1, b0);

		/*
		 * If the high-order bit of the type value is 0, this
		 * is a management frame.
		 * I.e, check "!(link[0] & 0x08)".
		 */
		s = gen_load_a(OR_LINK, 0, BPF_B);
		b2 = new_block(JMP(BPF_JSET));
		b2->s.k = 0x08;
		b2->stmts = s;
		gen_not(b2);

		/*
		 * For management frames, the DA is at 4.
		 */
		b1 = gen_bcmp(OR_LINK, 4, 6, eaddr);
		gen_and(b2, b1);

		/*
		 * OR that with the checks done for data frames.
		 * That gives the checks done for management and
		 * data frames.
		 */
		gen_or(b1, b0);

		/*
		 * If the low-order bit of the type value is 1,
		 * this is either a control frame or a frame
		 * with a reserved type, and thus not a
		 * frame with an SA.
		 *
		 * I.e., check "!(link[0] & 0x04)".
		 */
		s = gen_load_a(OR_LINK, 0, BPF_B);
		b1 = new_block(JMP(BPF_JSET));
		b1->s.k = 0x04;
		b1->stmts = s;
		gen_not(b1);

		/*
		 * AND that with the checks for data and management
		 * frames.
		 */
		gen_and(b1, b0);
		return b0;

	case Q_RA:
		/*
		 * Not present in management frames; addr1 in other
		 * frames.
		 */

		/*
		 * If the high-order bit of the type value is 0, this
		 * is a management frame.
		 * I.e, check "(link[0] & 0x08)".
		 */
		s = gen_load_a(OR_LINK, 0, BPF_B);
		b1 = new_block(JMP(BPF_JSET));
		b1->s.k = 0x08;
		b1->stmts = s;

		/*
		 * Check addr1.
		 */
		b0 = gen_bcmp(OR_LINK, 4, 6, eaddr);

		/*
		 * AND that with the check of addr1.
		 */
		gen_and(b1, b0);
		return (b0);

	case Q_TA:
		/*
		 * Not present in management frames; addr2, if present,
		 * in other frames.
		 */

		/*
		 * Not present in CTS or ACK control frames.
		 */
		b0 = gen_mcmp(OR_LINK, 0, BPF_B, IEEE80211_FC0_TYPE_CTL,
			IEEE80211_FC0_TYPE_MASK);
		gen_not(b0);
		b1 = gen_mcmp(OR_LINK, 0, BPF_B, IEEE80211_FC0_SUBTYPE_CTS,
			IEEE80211_FC0_SUBTYPE_MASK);
		gen_not(b1);
		b2 = gen_mcmp(OR_LINK, 0, BPF_B, IEEE80211_FC0_SUBTYPE_ACK,
			IEEE80211_FC0_SUBTYPE_MASK);
		gen_not(b2);
		gen_and(b1, b2);
		gen_or(b0, b2);

		/*
		 * If the high-order bit of the type value is 0, this
		 * is a management frame.
		 * I.e, check "(link[0] & 0x08)".
		 */
		s = gen_load_a(OR_LINK, 0, BPF_B);
		b1 = new_block(JMP(BPF_JSET));
		b1->s.k = 0x08;
		b1->stmts = s;

		/*
		 * AND that with the check for frames other than
		 * CTS and ACK frames.
		 */
		gen_and(b1, b2);

		/*
		 * Check addr2.
		 */
		b1 = gen_bcmp(OR_LINK, 10, 6, eaddr);
		gen_and(b2, b1);
		return b1;

	/*
	 * XXX - add BSSID keyword?
	 */
	case Q_ADDR1:
		return (gen_bcmp(OR_LINK, 4, 6, eaddr));

	case Q_ADDR2:
		/*
		 * Not present in CTS or ACK control frames.
		 */
		b0 = gen_mcmp(OR_LINK, 0, BPF_B, IEEE80211_FC0_TYPE_CTL,
			IEEE80211_FC0_TYPE_MASK);
		gen_not(b0);
		b1 = gen_mcmp(OR_LINK, 0, BPF_B, IEEE80211_FC0_SUBTYPE_CTS,
			IEEE80211_FC0_SUBTYPE_MASK);
		gen_not(b1);
		b2 = gen_mcmp(OR_LINK, 0, BPF_B, IEEE80211_FC0_SUBTYPE_ACK,
			IEEE80211_FC0_SUBTYPE_MASK);
		gen_not(b2);
		gen_and(b1, b2);
		gen_or(b0, b2);
		b1 = gen_bcmp(OR_LINK, 10, 6, eaddr);
		gen_and(b2, b1);
		return b1;

	case Q_ADDR3:
		/*
		 * Not present in control frames.
		 */
		b0 = gen_mcmp(OR_LINK, 0, BPF_B, IEEE80211_FC0_TYPE_CTL,
			IEEE80211_FC0_TYPE_MASK);
		gen_not(b0);
		b1 = gen_bcmp(OR_LINK, 16, 6, eaddr);
		gen_and(b0, b1);
		return b1;

	case Q_ADDR4:
		/*
		 * Present only if the direction mask has both "From DS"
		 * and "To DS" set.  Neither control frames nor management
		 * frames should have both of those set, so we don't
		 * check the frame type.
		 */
		b0 = gen_mcmp(OR_LINK, 1, BPF_B,
			IEEE80211_FC1_DIR_DSTODS, IEEE80211_FC1_DIR_MASK);
		b1 = gen_bcmp(OR_LINK, 24, 6, eaddr);
		gen_and(b0, b1);
		return b1;

	case Q_AND:
		b0 = gen_wlanhostop(eaddr, Q_SRC);
		b1 = gen_wlanhostop(eaddr, Q_DST);
		gen_and(b0, b1);
		return b1;

	case Q_DEFAULT:
	case Q_OR:
		b0 = gen_wlanhostop(eaddr, Q_SRC);
		b1 = gen_wlanhostop(eaddr, Q_DST);
		gen_or(b0, b1);
		return b1;
	}
	abort();
	/* NOTREACHED */
}

/*
 * Like gen_ehostop, but for RFC 2625 IP-over-Fibre-Channel.
 * (We assume that the addresses are IEEE 48-bit MAC addresses,
 * as the RFC states.)
 */
static struct block *
gen_ipfchostop(eaddr, dir)
	register const u_char *eaddr;
	register int dir;
{
	register struct block *b0, *b1;

	switch (dir) {
	case Q_SRC:
		return gen_bcmp(OR_LINK, 10, 6, eaddr);

	case Q_DST:
		return gen_bcmp(OR_LINK, 2, 6, eaddr);

	case Q_AND:
		b0 = gen_ipfchostop(eaddr, Q_SRC);
		b1 = gen_ipfchostop(eaddr, Q_DST);
		gen_and(b0, b1);
		return b1;

	case Q_DEFAULT:
	case Q_OR:
		b0 = gen_ipfchostop(eaddr, Q_SRC);
		b1 = gen_ipfchostop(eaddr, Q_DST);
		gen_or(b0, b1);
		return b1;

	case Q_ADDR1:
		bpf_error("'addr1' is only supported on 802.11");
		break;

	case Q_ADDR2:
		bpf_error("'addr2' is only supported on 802.11");
		break;

	case Q_ADDR3:
		bpf_error("'addr3' is only supported on 802.11");
		break;

	case Q_ADDR4:
		bpf_error("'addr4' is only supported on 802.11");
		break;

	case Q_RA:
		bpf_error("'ra' is only supported on 802.11");
		break;

	case Q_TA:
		bpf_error("'ta' is only supported on 802.11");
		break;
	}
	abort();
	/* NOTREACHED */
}

/*
 * This is quite tricky because there may be pad bytes in front of the
 * DECNET header, and then there are two possible data packet formats that
 * carry both src and dst addresses, plus 5 packet types in a format that
 * carries only the src node, plus 2 types that use a different format and
 * also carry just the src node.
 *
 * Yuck.
 *
 * Instead of doing those all right, we just look for data packets with
 * 0 or 1 bytes of padding.  If you want to look at other packets, that
 * will require a lot more hacking.
 *
 * To add support for filtering on DECNET "areas" (network numbers)
 * one would want to add a "mask" argument to this routine.  That would
 * make the filter even more inefficient, although one could be clever
 * and not generate masking instructions if the mask is 0xFFFF.
 */
static struct block *
gen_dnhostop(addr, dir)
	bpf_u_int32 addr;
	int dir;
{
	struct block *b0, *b1, *b2, *tmp;
	u_int offset_lh;	/* offset if long header is received */
	u_int offset_sh;	/* offset if short header is received */

	switch (dir) {

	case Q_DST:
		offset_sh = 1;	/* follows flags */
		offset_lh = 7;	/* flgs,darea,dsubarea,HIORD */
		break;

	case Q_SRC:
		offset_sh = 3;	/* follows flags, dstnode */
		offset_lh = 15;	/* flgs,darea,dsubarea,did,sarea,ssub,HIORD */
		break;

	case Q_AND:
		/* Inefficient because we do our Calvinball dance twice */
		b0 = gen_dnhostop(addr, Q_SRC);
		b1 = gen_dnhostop(addr, Q_DST);
		gen_and(b0, b1);
		return b1;

	case Q_OR:
	case Q_DEFAULT:
		/* Inefficient because we do our Calvinball dance twice */
		b0 = gen_dnhostop(addr, Q_SRC);
		b1 = gen_dnhostop(addr, Q_DST);
		gen_or(b0, b1);
		return b1;

	case Q_ISO:
		bpf_error("ISO host filtering not implemented");

	default:
		abort();
	}
	b0 = gen_linktype(ETHERTYPE_DN);
	/* Check for pad = 1, long header case */
	tmp = gen_mcmp(OR_NET, 2, BPF_H,
	    (bpf_int32)ntohs(0x0681), (bpf_int32)ntohs(0x07FF));
	b1 = gen_cmp(OR_NET, 2 + 1 + offset_lh,
	    BPF_H, (bpf_int32)ntohs((u_short)addr));
	gen_and(tmp, b1);
	/* Check for pad = 0, long header case */
	tmp = gen_mcmp(OR_NET, 2, BPF_B, (bpf_int32)0x06, (bpf_int32)0x7);
	b2 = gen_cmp(OR_NET, 2 + offset_lh, BPF_H, (bpf_int32)ntohs((u_short)addr));
	gen_and(tmp, b2);
	gen_or(b2, b1);
	/* Check for pad = 1, short header case */
	tmp = gen_mcmp(OR_NET, 2, BPF_H,
	    (bpf_int32)ntohs(0x0281), (bpf_int32)ntohs(0x07FF));
	b2 = gen_cmp(OR_NET, 2 + 1 + offset_sh, BPF_H, (bpf_int32)ntohs((u_short)addr));
	gen_and(tmp, b2);
	gen_or(b2, b1);
	/* Check for pad = 0, short header case */
	tmp = gen_mcmp(OR_NET, 2, BPF_B, (bpf_int32)0x02, (bpf_int32)0x7);
	b2 = gen_cmp(OR_NET, 2 + offset_sh, BPF_H, (bpf_int32)ntohs((u_short)addr));
	gen_and(tmp, b2);
	gen_or(b2, b1);

	/* Combine with test for linktype */
	gen_and(b0, b1);
	return b1;
}

/*
 * Generate a check for IPv4 or IPv6 for MPLS-encapsulated packets;
 * test the bottom-of-stack bit, and then check the version number
 * field in the IP header.
 */
static struct block *
gen_mpls_linktype(proto)
	int proto;
{
	struct block *b0, *b1;

        switch (proto) {

        case Q_IP:
                /* match the bottom-of-stack bit */
                b0 = gen_mcmp(OR_NET, -2, BPF_B, 0x01, 0x01);
                /* match the IPv4 version number */
                b1 = gen_mcmp(OR_NET, 0, BPF_B, 0x40, 0xf0);
                gen_and(b0, b1);
                return b1;
 
       case Q_IPV6:
                /* match the bottom-of-stack bit */
                b0 = gen_mcmp(OR_NET, -2, BPF_B, 0x01, 0x01);
                /* match the IPv4 version number */
                b1 = gen_mcmp(OR_NET, 0, BPF_B, 0x60, 0xf0);
                gen_and(b0, b1);
                return b1;
 
       default:
                abort();
        }
}

static struct block *
gen_host(addr, mask, proto, dir, type)
	bpf_u_int32 addr;
	bpf_u_int32 mask;
	int proto;
	int dir;
	int type;
{
	struct block *b0, *b1;
	const char *typestr;

	if (type == Q_NET)
		typestr = "net";
	else
		typestr = "host";

	switch (proto) {

	case Q_DEFAULT:
		b0 = gen_host(addr, mask, Q_IP, dir, type);
		/*
		 * Only check for non-IPv4 addresses if we're not
		 * checking MPLS-encapsulated packets.
		 */
		if (label_stack_depth == 0) {
			b1 = gen_host(addr, mask, Q_ARP, dir, type);
			gen_or(b0, b1);
			b0 = gen_host(addr, mask, Q_RARP, dir, type);
			gen_or(b1, b0);
		}
		return b0;

	case Q_IP:
		return gen_hostop(addr, mask, dir, ETHERTYPE_IP, 12, 16);

	case Q_RARP:
		return gen_hostop(addr, mask, dir, ETHERTYPE_REVARP, 14, 24);

	case Q_ARP:
		return gen_hostop(addr, mask, dir, ETHERTYPE_ARP, 14, 24);

	case Q_TCP:
		bpf_error("'tcp' modifier applied to %s", typestr);

	case Q_SCTP:
		bpf_error("'sctp' modifier applied to %s", typestr);

	case Q_UDP:
		bpf_error("'udp' modifier applied to %s", typestr);

	case Q_ICMP:
		bpf_error("'icmp' modifier applied to %s", typestr);

	case Q_IGMP:
		bpf_error("'igmp' modifier applied to %s", typestr);

	case Q_IGRP:
		bpf_error("'igrp' modifier applied to %s", typestr);

	case Q_PIM:
		bpf_error("'pim' modifier applied to %s", typestr);

	case Q_VRRP:
		bpf_error("'vrrp' modifier applied to %s", typestr);

	case Q_CARP:
		bpf_error("'carp' modifier applied to %s", typestr);

	case Q_ATALK:
		bpf_error("ATALK host filtering not implemented");

	case Q_AARP:
		bpf_error("AARP host filtering not implemented");

	case Q_DECNET:
		return gen_dnhostop(addr, dir);

	case Q_SCA:
		bpf_error("SCA host filtering not implemented");

	case Q_LAT:
		bpf_error("LAT host filtering not implemented");

	case Q_MOPDL:
		bpf_error("MOPDL host filtering not implemented");

	case Q_MOPRC:
		bpf_error("MOPRC host filtering not implemented");

	case Q_IPV6:
		bpf_error("'ip6' modifier applied to ip host");

	case Q_ICMPV6:
		bpf_error("'icmp6' modifier applied to %s", typestr);

	case Q_AH:
		bpf_error("'ah' modifier applied to %s", typestr);

	case Q_ESP:
		bpf_error("'esp' modifier applied to %s", typestr);

	case Q_ISO:
		bpf_error("ISO host filtering not implemented");

	case Q_ESIS:
		bpf_error("'esis' modifier applied to %s", typestr);

	case Q_ISIS:
		bpf_error("'isis' modifier applied to %s", typestr);

	case Q_CLNP:
		bpf_error("'clnp' modifier applied to %s", typestr);

	case Q_STP:
		bpf_error("'stp' modifier applied to %s", typestr);

	case Q_IPX:
		bpf_error("IPX host filtering not implemented");

	case Q_NETBEUI:
		bpf_error("'netbeui' modifier applied to %s", typestr);

	case Q_RADIO:
		bpf_error("'radio' modifier applied to %s", typestr);

	default:
		abort();
	}
	/* NOTREACHED */
}

#ifdef INET6
static struct block *
gen_host6(addr, mask, proto, dir, type)
	struct in6_addr *addr;
	struct in6_addr *mask;
	int proto;
	int dir;
	int type;
{
	const char *typestr;

	if (type == Q_NET)
		typestr = "net";
	else
		typestr = "host";

	switch (proto) {

	case Q_DEFAULT:
		return gen_host6(addr, mask, Q_IPV6, dir, type);

	case Q_LINK:
		bpf_error("link-layer modifier applied to ip6 %s", typestr);

	case Q_IP:
		bpf_error("'ip' modifier applied to ip6 %s", typestr);

	case Q_RARP:
		bpf_error("'rarp' modifier applied to ip6 %s", typestr);

	case Q_ARP:
		bpf_error("'arp' modifier applied to ip6 %s", typestr);

	case Q_SCTP:
		bpf_error("'sctp' modifier applied to %s", typestr);

	case Q_TCP:
		bpf_error("'tcp' modifier applied to %s", typestr);

	case Q_UDP:
		bpf_error("'udp' modifier applied to %s", typestr);

	case Q_ICMP:
		bpf_error("'icmp' modifier applied to %s", typestr);

	case Q_IGMP:
		bpf_error("'igmp' modifier applied to %s", typestr);

	case Q_IGRP:
		bpf_error("'igrp' modifier applied to %s", typestr);

	case Q_PIM:
		bpf_error("'pim' modifier applied to %s", typestr);

	case Q_VRRP:
		bpf_error("'vrrp' modifier applied to %s", typestr);

	case Q_CARP:
		bpf_error("'carp' modifier applied to %s", typestr);

	case Q_ATALK:
		bpf_error("ATALK host filtering not implemented");

	case Q_AARP:
		bpf_error("AARP host filtering not implemented");

	case Q_DECNET:
		bpf_error("'decnet' modifier applied to ip6 %s", typestr);

	case Q_SCA:
		bpf_error("SCA host filtering not implemented");

	case Q_LAT:
		bpf_error("LAT host filtering not implemented");

	case Q_MOPDL:
		bpf_error("MOPDL host filtering not implemented");

	case Q_MOPRC:
		bpf_error("MOPRC host filtering not implemented");

	case Q_IPV6:
		return gen_hostop6(addr, mask, dir, ETHERTYPE_IPV6, 8, 24);

	case Q_ICMPV6:
		bpf_error("'icmp6' modifier applied to %s", typestr);

	case Q_AH:
		bpf_error("'ah' modifier applied to %s", typestr);

	case Q_ESP:
		bpf_error("'esp' modifier applied to %s", typestr);

	case Q_ISO:
		bpf_error("ISO host filtering not implemented");

	case Q_ESIS:
		bpf_error("'esis' modifier applied to %s", typestr);

	case Q_ISIS:
		bpf_error("'isis' modifier applied to %s", typestr);

	case Q_CLNP:
		bpf_error("'clnp' modifier applied to %s", typestr);

	case Q_STP:
		bpf_error("'stp' modifier applied to %s", typestr);

	case Q_IPX:
		bpf_error("IPX host filtering not implemented");

	case Q_NETBEUI:
		bpf_error("'netbeui' modifier applied to %s", typestr);

	case Q_RADIO:
		bpf_error("'radio' modifier applied to %s", typestr);

	default:
		abort();
	}
	/* NOTREACHED */
}
#endif

#ifndef INET6
static struct block *
gen_gateway(eaddr, alist, proto, dir)
	const u_char *eaddr;
	bpf_u_int32 **alist;
	int proto;
	int dir;
{
	struct block *b0, *b1, *tmp;

	if (dir != 0)
		bpf_error("direction applied to 'gateway'");

	switch (proto) {
	case Q_DEFAULT:
	case Q_IP:
	case Q_ARP:
	case Q_RARP:
		switch (linktype) {
		case DLT_EN10MB:
		case DLT_NETANALYZER:
		case DLT_NETANALYZER_TRANSPARENT:
			b0 = gen_ehostop(eaddr, Q_OR);
			break;
		case DLT_FDDI:
			b0 = gen_fhostop(eaddr, Q_OR);
			break;
		case DLT_IEEE802:
			b0 = gen_thostop(eaddr, Q_OR);
			break;
		case DLT_IEEE802_11:
		case DLT_PRISM_HEADER:
		case DLT_IEEE802_11_RADIO_AVS:
		case DLT_IEEE802_11_RADIO:
		case DLT_PPI:
			b0 = gen_wlanhostop(eaddr, Q_OR);
			break;
		case DLT_SUNATM:
			if (!is_lane)
				bpf_error(
				    "'gateway' supported only on ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel");
			/*
			 * Check that the packet doesn't begin with an
			 * LE Control marker.  (We've already generated
			 * a test for LANE.)
			 */
			b1 = gen_cmp(OR_LINK, SUNATM_PKT_BEGIN_POS,
			    BPF_H, 0xFF00);
			gen_not(b1);

			/*
			 * Now check the MAC address.
			 */
			b0 = gen_ehostop(eaddr, Q_OR);
			gen_and(b1, b0);
			break;
		case DLT_IP_OVER_FC:
			b0 = gen_ipfchostop(eaddr, Q_OR);
			break;
		default:
			bpf_error(
			    "'gateway' supported only on ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel");
		}
		b1 = gen_host(**alist++, 0xffffffff, proto, Q_OR, Q_HOST);
		while (*alist) {
			tmp = gen_host(**alist++, 0xffffffff, proto, Q_OR,
			    Q_HOST);
			gen_or(b1, tmp);
			b1 = tmp;
		}
		gen_not(b1);
		gen_and(b0, b1);
		return b1;
	}
	bpf_error("illegal modifier of 'gateway'");
	/* NOTREACHED */
}
#endif

struct block *
gen_proto_abbrev(proto)
	int proto;
{
	struct block *b0;
	struct block *b1;

	switch (proto) {

	case Q_SCTP:
		b1 = gen_proto(IPPROTO_SCTP, Q_IP, Q_DEFAULT);
		b0 = gen_proto(IPPROTO_SCTP, Q_IPV6, Q_DEFAULT);
		gen_or(b0, b1);
		break;

	case Q_TCP:
		b1 = gen_proto(IPPROTO_TCP, Q_IP, Q_DEFAULT);
		b0 = gen_proto(IPPROTO_TCP, Q_IPV6, Q_DEFAULT);
		gen_or(b0, b1);
		break;

	case Q_UDP:
		b1 = gen_proto(IPPROTO_UDP, Q_IP, Q_DEFAULT);
		b0 = gen_proto(IPPROTO_UDP, Q_IPV6, Q_DEFAULT);
		gen_or(b0, b1);
		break;

	case Q_ICMP:
		b1 = gen_proto(IPPROTO_ICMP, Q_IP, Q_DEFAULT);
		break;

#ifndef	IPPROTO_IGMP
#define	IPPROTO_IGMP	2
#endif

	case Q_IGMP:
		b1 = gen_proto(IPPROTO_IGMP, Q_IP, Q_DEFAULT);
		break;

#ifndef	IPPROTO_IGRP
#define	IPPROTO_IGRP	9
#endif
	case Q_IGRP:
		b1 = gen_proto(IPPROTO_IGRP, Q_IP, Q_DEFAULT);
		break;

#ifndef IPPROTO_PIM
#define IPPROTO_PIM	103
#endif

	case Q_PIM:
		b1 = gen_proto(IPPROTO_PIM, Q_IP, Q_DEFAULT);
		b0 = gen_proto(IPPROTO_PIM, Q_IPV6, Q_DEFAULT);
		gen_or(b0, b1);
		break;

#ifndef IPPROTO_VRRP
#define IPPROTO_VRRP	112
#endif

	case Q_VRRP:
		b1 = gen_proto(IPPROTO_VRRP, Q_IP, Q_DEFAULT);
		break;

#ifndef IPPROTO_CARP
#define IPPROTO_CARP	112
#endif

	case Q_CARP:
		b1 = gen_proto(IPPROTO_CARP, Q_IP, Q_DEFAULT);
		break;

	case Q_IP:
		b1 =  gen_linktype(ETHERTYPE_IP);
		break;

	case Q_ARP:
		b1 =  gen_linktype(ETHERTYPE_ARP);
		break;

	case Q_RARP:
		b1 =  gen_linktype(ETHERTYPE_REVARP);
		break;

	case Q_LINK:
		bpf_error("link layer applied in wrong context");

	case Q_ATALK:
		b1 =  gen_linktype(ETHERTYPE_ATALK);
		break;

	case Q_AARP:
		b1 =  gen_linktype(ETHERTYPE_AARP);
		break;

	case Q_DECNET:
		b1 =  gen_linktype(ETHERTYPE_DN);
		break;

	case Q_SCA:
		b1 =  gen_linktype(ETHERTYPE_SCA);
		break;

	case Q_LAT:
		b1 =  gen_linktype(ETHERTYPE_LAT);
		break;

	case Q_MOPDL:
		b1 =  gen_linktype(ETHERTYPE_MOPDL);
		break;

	case Q_MOPRC:
		b1 =  gen_linktype(ETHERTYPE_MOPRC);
		break;

	case Q_IPV6:
		b1 = gen_linktype(ETHERTYPE_IPV6);
		break;

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6	58
#endif
	case Q_ICMPV6:
		b1 = gen_proto(IPPROTO_ICMPV6, Q_IPV6, Q_DEFAULT);
		break;

#ifndef IPPROTO_AH
#define IPPROTO_AH	51
#endif
	case Q_AH:
		b1 = gen_proto(IPPROTO_AH, Q_IP, Q_DEFAULT);
		b0 = gen_proto(IPPROTO_AH, Q_IPV6, Q_DEFAULT);
		gen_or(b0, b1);
		break;

#ifndef IPPROTO_ESP
#define IPPROTO_ESP	50
#endif
	case Q_ESP:
		b1 = gen_proto(IPPROTO_ESP, Q_IP, Q_DEFAULT);
		b0 = gen_proto(IPPROTO_ESP, Q_IPV6, Q_DEFAULT);
		gen_or(b0, b1);
		break;

	case Q_ISO:
		b1 = gen_linktype(LLCSAP_ISONS);
		break;

	case Q_ESIS:
		b1 = gen_proto(ISO9542_ESIS, Q_ISO, Q_DEFAULT);
		break;

	case Q_ISIS:
		b1 = gen_proto(ISO10589_ISIS, Q_ISO, Q_DEFAULT);
		break;

	case Q_ISIS_L1: /* all IS-IS Level1 PDU-Types */
		b0 = gen_proto(ISIS_L1_LAN_IIH, Q_ISIS, Q_DEFAULT);
		b1 = gen_proto(ISIS_PTP_IIH, Q_ISIS, Q_DEFAULT); /* FIXME extract the circuit-type bits */
		gen_or(b0, b1);
		b0 = gen_proto(ISIS_L1_LSP, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		b0 = gen_proto(ISIS_L1_CSNP, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		b0 = gen_proto(ISIS_L1_PSNP, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		break;

	case Q_ISIS_L2: /* all IS-IS Level2 PDU-Types */
		b0 = gen_proto(ISIS_L2_LAN_IIH, Q_ISIS, Q_DEFAULT);
		b1 = gen_proto(ISIS_PTP_IIH, Q_ISIS, Q_DEFAULT); /* FIXME extract the circuit-type bits */
		gen_or(b0, b1);
		b0 = gen_proto(ISIS_L2_LSP, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		b0 = gen_proto(ISIS_L2_CSNP, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		b0 = gen_proto(ISIS_L2_PSNP, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		break;

	case Q_ISIS_IIH: /* all IS-IS Hello PDU-Types */
		b0 = gen_proto(ISIS_L1_LAN_IIH, Q_ISIS, Q_DEFAULT);
		b1 = gen_proto(ISIS_L2_LAN_IIH, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		b0 = gen_proto(ISIS_PTP_IIH, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		break;

	case Q_ISIS_LSP:
		b0 = gen_proto(ISIS_L1_LSP, Q_ISIS, Q_DEFAULT);
		b1 = gen_proto(ISIS_L2_LSP, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		break;

	case Q_ISIS_SNP:
		b0 = gen_proto(ISIS_L1_CSNP, Q_ISIS, Q_DEFAULT);
		b1 = gen_proto(ISIS_L2_CSNP, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		b0 = gen_proto(ISIS_L1_PSNP, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		b0 = gen_proto(ISIS_L2_PSNP, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		break;

	case Q_ISIS_CSNP:
		b0 = gen_proto(ISIS_L1_CSNP, Q_ISIS, Q_DEFAULT);
		b1 = gen_proto(ISIS_L2_CSNP, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		break;

	case Q_ISIS_PSNP:
		b0 = gen_proto(ISIS_L1_PSNP, Q_ISIS, Q_DEFAULT);
		b1 = gen_proto(ISIS_L2_PSNP, Q_ISIS, Q_DEFAULT);
		gen_or(b0, b1);
		break;

	case Q_CLNP:
		b1 = gen_proto(ISO8473_CLNP, Q_ISO, Q_DEFAULT);
		break;

	case Q_STP:
		b1 = gen_linktype(LLCSAP_8021D);
		break;

	case Q_IPX:
		b1 = gen_linktype(LLCSAP_IPX);
		break;

	case Q_NETBEUI:
		b1 = gen_linktype(LLCSAP_NETBEUI);
		break;

	case Q_RADIO:
		bpf_error("'radio' is not a valid protocol type");

	default:
		abort();
	}
	return b1;
}

static struct block *
gen_ipfrag()
{
	struct slist *s;
	struct block *b;

	/* not IPv4 frag other than the first frag */
	s = gen_load_a(OR_NET, 6, BPF_H);
	b = new_block(JMP(BPF_JSET));
	b->s.k = 0x1fff;
	b->stmts = s;
	gen_not(b);

	return b;
}

/*
 * Generate a comparison to a port value in the transport-layer header
 * at the specified offset from the beginning of that header.
 *
 * XXX - this handles a variable-length prefix preceding the link-layer
 * header, such as the radiotap or AVS radio prefix, but doesn't handle
 * variable-length link-layer headers (such as Token Ring or 802.11
 * headers).
 */
static struct block *
gen_portatom(off, v)
	int off;
	bpf_int32 v;
{
	return gen_cmp(OR_TRAN_IPV4, off, BPF_H, v);
}

static struct block *
gen_portatom6(off, v)
	int off;
	bpf_int32 v;
{
	return gen_cmp(OR_TRAN_IPV6, off, BPF_H, v);
}

struct block *
gen_portop(port, proto, dir)
	int port, proto, dir;
{
	struct block *b0, *b1, *tmp;

	/* ip proto 'proto' and not a fragment other than the first fragment */
	tmp = gen_cmp(OR_NET, 9, BPF_B, (bpf_int32)proto);
	b0 = gen_ipfrag();
	gen_and(tmp, b0);

	switch (dir) {
	case Q_SRC:
		b1 = gen_portatom(0, (bpf_int32)port);
		break;

	case Q_DST:
		b1 = gen_portatom(2, (bpf_int32)port);
		break;

	case Q_OR:
	case Q_DEFAULT:
		tmp = gen_portatom(0, (bpf_int32)port);
		b1 = gen_portatom(2, (bpf_int32)port);
		gen_or(tmp, b1);
		break;

	case Q_AND:
		tmp = gen_portatom(0, (bpf_int32)port);
		b1 = gen_portatom(2, (bpf_int32)port);
		gen_and(tmp, b1);
		break;

	default:
		abort();
	}
	gen_and(b0, b1);

	return b1;
}

static struct block *
gen_port(port, ip_proto, dir)
	int port;
	int ip_proto;
	int dir;
{
	struct block *b0, *b1, *tmp;

	/*
	 * ether proto ip
	 *
	 * For FDDI, RFC 1188 says that SNAP encapsulation is used,
	 * not LLC encapsulation with LLCSAP_IP.
	 *
	 * For IEEE 802 networks - which includes 802.5 token ring
	 * (which is what DLT_IEEE802 means) and 802.11 - RFC 1042
	 * says that SNAP encapsulation is used, not LLC encapsulation
	 * with LLCSAP_IP.
	 *
	 * For LLC-encapsulated ATM/"Classical IP", RFC 1483 and
	 * RFC 2225 say that SNAP encapsulation is used, not LLC
	 * encapsulation with LLCSAP_IP.
	 *
	 * So we always check for ETHERTYPE_IP.
	 */
	b0 =  gen_linktype(ETHERTYPE_IP);

	switch (ip_proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
		b1 = gen_portop(port, ip_proto, dir);
		break;

	case PROTO_UNDEF:
		tmp = gen_portop(port, IPPROTO_TCP, dir);
		b1 = gen_portop(port, IPPROTO_UDP, dir);
		gen_or(tmp, b1);
		tmp = gen_portop(port, IPPROTO_SCTP, dir);
		gen_or(tmp, b1);
		break;

	default:
		abort();
	}
	gen_and(b0, b1);
	return b1;
}

struct block *
gen_portop6(port, proto, dir)
	int port, proto, dir;
{
	struct block *b0, *b1, *tmp;

	/* ip6 proto 'proto' */
	/* XXX - catch the first fragment of a fragmented packet? */
	b0 = gen_cmp(OR_NET, 6, BPF_B, (bpf_int32)proto);

	switch (dir) {
	case Q_SRC:
		b1 = gen_portatom6(0, (bpf_int32)port);
		break;

	case Q_DST:
		b1 = gen_portatom6(2, (bpf_int32)port);
		break;

	case Q_OR:
	case Q_DEFAULT:
		tmp = gen_portatom6(0, (bpf_int32)port);
		b1 = gen_portatom6(2, (bpf_int32)port);
		gen_or(tmp, b1);
		break;

	case Q_AND:
		tmp = gen_portatom6(0, (bpf_int32)port);
		b1 = gen_portatom6(2, (bpf_int32)port);
		gen_and(tmp, b1);
		break;

	default:
		abort();
	}
	gen_and(b0, b1);

	return b1;
}

static struct block *
gen_port6(port, ip_proto, dir)
	int port;
	int ip_proto;
	int dir;
{
	struct block *b0, *b1, *tmp;

	/* link proto ip6 */
	b0 =  gen_linktype(ETHERTYPE_IPV6);

	switch (ip_proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
		b1 = gen_portop6(port, ip_proto, dir);
		break;

	case PROTO_UNDEF:
		tmp = gen_portop6(port, IPPROTO_TCP, dir);
		b1 = gen_portop6(port, IPPROTO_UDP, dir);
		gen_or(tmp, b1);
		tmp = gen_portop6(port, IPPROTO_SCTP, dir);
		gen_or(tmp, b1);
		break;

	default:
		abort();
	}
	gen_and(b0, b1);
	return b1;
}

/* gen_portrange code */
static struct block *
gen_portrangeatom(off, v1, v2)
	int off;
	bpf_int32 v1, v2;
{
	struct block *b1, *b2;

	if (v1 > v2) {
		/*
		 * Reverse the order of the ports, so v1 is the lower one.
		 */
		bpf_int32 vtemp;

		vtemp = v1;
		v1 = v2;
		v2 = vtemp;
	}

	b1 = gen_cmp_ge(OR_TRAN_IPV4, off, BPF_H, v1);
	b2 = gen_cmp_le(OR_TRAN_IPV4, off, BPF_H, v2);

	gen_and(b1, b2); 

	return b2;
}

struct block *
gen_portrangeop(port1, port2, proto, dir)
	int port1, port2;
	int proto;
	int dir;
{
	struct block *b0, *b1, *tmp;

	/* ip proto 'proto' and not a fragment other than the first fragment */
	tmp = gen_cmp(OR_NET, 9, BPF_B, (bpf_int32)proto);
	b0 = gen_ipfrag();
	gen_and(tmp, b0);

	switch (dir) {
	case Q_SRC:
		b1 = gen_portrangeatom(0, (bpf_int32)port1, (bpf_int32)port2);
		break;

	case Q_DST:
		b1 = gen_portrangeatom(2, (bpf_int32)port1, (bpf_int32)port2);
		break;

	case Q_OR:
	case Q_DEFAULT:
		tmp = gen_portrangeatom(0, (bpf_int32)port1, (bpf_int32)port2);
		b1 = gen_portrangeatom(2, (bpf_int32)port1, (bpf_int32)port2);
		gen_or(tmp, b1);
		break;

	case Q_AND:
		tmp = gen_portrangeatom(0, (bpf_int32)port1, (bpf_int32)port2);
		b1 = gen_portrangeatom(2, (bpf_int32)port1, (bpf_int32)port2);
		gen_and(tmp, b1);
		break;

	default:
		abort();
	}
	gen_and(b0, b1);

	return b1;
}

static struct block *
gen_portrange(port1, port2, ip_proto, dir)
	int port1, port2;
	int ip_proto;
	int dir;
{
	struct block *b0, *b1, *tmp;

	/* link proto ip */
	b0 =  gen_linktype(ETHERTYPE_IP);

	switch (ip_proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
		b1 = gen_portrangeop(port1, port2, ip_proto, dir);
		break;

	case PROTO_UNDEF:
		tmp = gen_portrangeop(port1, port2, IPPROTO_TCP, dir);
		b1 = gen_portrangeop(port1, port2, IPPROTO_UDP, dir);
		gen_or(tmp, b1);
		tmp = gen_portrangeop(port1, port2, IPPROTO_SCTP, dir);
		gen_or(tmp, b1);
		break;

	default:
		abort();
	}
	gen_and(b0, b1);
	return b1;
}

static struct block *
gen_portrangeatom6(off, v1, v2)
	int off;
	bpf_int32 v1, v2;
{
	struct block *b1, *b2;

	if (v1 > v2) {
		/*
		 * Reverse the order of the ports, so v1 is the lower one.
		 */
		bpf_int32 vtemp;

		vtemp = v1;
		v1 = v2;
		v2 = vtemp;
	}

	b1 = gen_cmp_ge(OR_TRAN_IPV6, off, BPF_H, v1);
	b2 = gen_cmp_le(OR_TRAN_IPV6, off, BPF_H, v2);

	gen_and(b1, b2); 

	return b2;
}

struct block *
gen_portrangeop6(port1, port2, proto, dir)
	int port1, port2;
	int proto;
	int dir;
{
	struct block *b0, *b1, *tmp;

	/* ip6 proto 'proto' */
	/* XXX - catch the first fragment of a fragmented packet? */
	b0 = gen_cmp(OR_NET, 6, BPF_B, (bpf_int32)proto);

	switch (dir) {
	case Q_SRC:
		b1 = gen_portrangeatom6(0, (bpf_int32)port1, (bpf_int32)port2);
		break;

	case Q_DST:
		b1 = gen_portrangeatom6(2, (bpf_int32)port1, (bpf_int32)port2);
		break;

	case Q_OR:
	case Q_DEFAULT:
		tmp = gen_portrangeatom6(0, (bpf_int32)port1, (bpf_int32)port2);
		b1 = gen_portrangeatom6(2, (bpf_int32)port1, (bpf_int32)port2);
		gen_or(tmp, b1);
		break;

	case Q_AND:
		tmp = gen_portrangeatom6(0, (bpf_int32)port1, (bpf_int32)port2);
		b1 = gen_portrangeatom6(2, (bpf_int32)port1, (bpf_int32)port2);
		gen_and(tmp, b1);
		break;

	default:
		abort();
	}
	gen_and(b0, b1);

	return b1;
}

static struct block *
gen_portrange6(port1, port2, ip_proto, dir)
	int port1, port2;
	int ip_proto;
	int dir;
{
	struct block *b0, *b1, *tmp;

	/* link proto ip6 */
	b0 =  gen_linktype(ETHERTYPE_IPV6);

	switch (ip_proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
		b1 = gen_portrangeop6(port1, port2, ip_proto, dir);
		break;

	case PROTO_UNDEF:
		tmp = gen_portrangeop6(port1, port2, IPPROTO_TCP, dir);
		b1 = gen_portrangeop6(port1, port2, IPPROTO_UDP, dir);
		gen_or(tmp, b1);
		tmp = gen_portrangeop6(port1, port2, IPPROTO_SCTP, dir);
		gen_or(tmp, b1);
		break;

	default:
		abort();
	}
	gen_and(b0, b1);
	return b1;
}

static int
lookup_proto(name, proto)
	register const char *name;
	register int proto;
{
	register int v;

	switch (proto) {

	case Q_DEFAULT:
	case Q_IP:
	case Q_IPV6:
		v = pcap_nametoproto(name);
		if (v == PROTO_UNDEF)
			bpf_error("unknown ip proto '%s'", name);
		break;

	case Q_LINK:
		/* XXX should look up h/w protocol type based on linktype */
		v = pcap_nametoeproto(name);
		if (v == PROTO_UNDEF) {
			v = pcap_nametollc(name);
			if (v == PROTO_UNDEF)
				bpf_error("unknown ether proto '%s'", name);
		}
		break;

	case Q_ISO:
		if (strcmp(name, "esis") == 0)
			v = ISO9542_ESIS;
		else if (strcmp(name, "isis") == 0)
			v = ISO10589_ISIS;
		else if (strcmp(name, "clnp") == 0)
			v = ISO8473_CLNP;
		else
			bpf_error("unknown osi proto '%s'", name);
		break;

	default:
		v = PROTO_UNDEF;
		break;
	}
	return v;
}

#if 0
struct stmt *
gen_joinsp(s, n)
	struct stmt **s;
	int n;
{
	return NULL;
}
#endif

static struct block *
gen_protochain(v, proto, dir)
	int v;
	int proto;
	int dir;
{
#ifdef NO_PROTOCHAIN
	return gen_proto(v, proto, dir);
#else
	struct block *b0, *b;
	struct slist *s[100];
	int fix2, fix3, fix4, fix5;
	int ahcheck, again, end;
	int i, max;
	int reg2 = alloc_reg();

	memset(s, 0, sizeof(s));
	fix2 = fix3 = fix4 = fix5 = 0;

	switch (proto) {
	case Q_IP:
	case Q_IPV6:
		break;
	case Q_DEFAULT:
		b0 = gen_protochain(v, Q_IP, dir);
		b = gen_protochain(v, Q_IPV6, dir);
		gen_or(b0, b);
		return b;
	default:
		bpf_error("bad protocol applied for 'protochain'");
		/*NOTREACHED*/
	}

	/*
	 * We don't handle variable-length prefixes before the link-layer
	 * header, or variable-length link-layer headers, here yet.
	 * We might want to add BPF instructions to do the protochain
	 * work, to simplify that and, on platforms that have a BPF
	 * interpreter with the new instructions, let the filtering
	 * be done in the kernel.  (We already require a modified BPF
	 * engine to do the protochain stuff, to support backward
	 * branches, and backward branch support is unlikely to appear
	 * in kernel BPF engines.)
	 */
	switch (linktype) {

	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
	case DLT_PPI:
		bpf_error("'protochain' not supported with 802.11");
	}

	no_optimize = 1; /*this code is not compatible with optimzer yet */

	/*
	 * s[0] is a dummy entry to protect other BPF insn from damage
	 * by s[fix] = foo with uninitialized variable "fix".  It is somewhat
	 * hard to find interdependency made by jump table fixup.
	 */
	i = 0;
	s[i] = new_stmt(0);	/*dummy*/
	i++;

	switch (proto) {
	case Q_IP:
		b0 = gen_linktype(ETHERTYPE_IP);

		/* A = ip->ip_p */
		s[i] = new_stmt(BPF_LD|BPF_ABS|BPF_B);
		s[i]->s.k = off_macpl + off_nl + 9;
		i++;
		/* X = ip->ip_hl << 2 */
		s[i] = new_stmt(BPF_LDX|BPF_MSH|BPF_B);
		s[i]->s.k = off_macpl + off_nl;
		i++;
		break;

	case Q_IPV6:
		b0 = gen_linktype(ETHERTYPE_IPV6);

		/* A = ip6->ip_nxt */
		s[i] = new_stmt(BPF_LD|BPF_ABS|BPF_B);
		s[i]->s.k = off_macpl + off_nl + 6;
		i++;
		/* X = sizeof(struct ip6_hdr) */
		s[i] = new_stmt(BPF_LDX|BPF_IMM);
		s[i]->s.k = 40;
		i++;
		break;

	default:
		bpf_error("unsupported proto to gen_protochain");
		/*NOTREACHED*/
	}

	/* again: if (A == v) goto end; else fall through; */
	again = i;
	s[i] = new_stmt(BPF_JMP|BPF_JEQ|BPF_K);
	s[i]->s.k = v;
	s[i]->s.jt = NULL;		/*later*/
	s[i]->s.jf = NULL;		/*update in next stmt*/
	fix5 = i;
	i++;

#ifndef IPPROTO_NONE
#define IPPROTO_NONE	59
#endif
	/* if (A == IPPROTO_NONE) goto end */
	s[i] = new_stmt(BPF_JMP|BPF_JEQ|BPF_K);
	s[i]->s.jt = NULL;	/*later*/
	s[i]->s.jf = NULL;	/*update in next stmt*/
	s[i]->s.k = IPPROTO_NONE;
	s[fix5]->s.jf = s[i];
	fix2 = i;
	i++;

	if (proto == Q_IPV6) {
		int v6start, v6end, v6advance, j;

		v6start = i;
		/* if (A == IPPROTO_HOPOPTS) goto v6advance */
		s[i] = new_stmt(BPF_JMP|BPF_JEQ|BPF_K);
		s[i]->s.jt = NULL;	/*later*/
		s[i]->s.jf = NULL;	/*update in next stmt*/
		s[i]->s.k = IPPROTO_HOPOPTS;
		s[fix2]->s.jf = s[i];
		i++;
		/* if (A == IPPROTO_DSTOPTS) goto v6advance */
		s[i - 1]->s.jf = s[i] = new_stmt(BPF_JMP|BPF_JEQ|BPF_K);
		s[i]->s.jt = NULL;	/*later*/
		s[i]->s.jf = NULL;	/*update in next stmt*/
		s[i]->s.k = IPPROTO_DSTOPTS;
		i++;
		/* if (A == IPPROTO_ROUTING) goto v6advance */
		s[i - 1]->s.jf = s[i] = new_stmt(BPF_JMP|BPF_JEQ|BPF_K);
		s[i]->s.jt = NULL;	/*later*/
		s[i]->s.jf = NULL;	/*update in next stmt*/
		s[i]->s.k = IPPROTO_ROUTING;
		i++;
		/* if (A == IPPROTO_FRAGMENT) goto v6advance; else goto ahcheck; */
		s[i - 1]->s.jf = s[i] = new_stmt(BPF_JMP|BPF_JEQ|BPF_K);
		s[i]->s.jt = NULL;	/*later*/
		s[i]->s.jf = NULL;	/*later*/
		s[i]->s.k = IPPROTO_FRAGMENT;
		fix3 = i;
		v6end = i;
		i++;

		/* v6advance: */
		v6advance = i;

		/*
		 * in short,
		 * A = P[X + packet head];
		 * X = X + (P[X + packet head + 1] + 1) * 8;
		 */
		/* A = P[X + packet head] */
		s[i] = new_stmt(BPF_LD|BPF_IND|BPF_B);
		s[i]->s.k = off_macpl + off_nl;
		i++;
		/* MEM[reg2] = A */
		s[i] = new_stmt(BPF_ST);
		s[i]->s.k = reg2;
		i++;
		/* A = P[X + packet head + 1]; */
		s[i] = new_stmt(BPF_LD|BPF_IND|BPF_B);
		s[i]->s.k = off_macpl + off_nl + 1;
		i++;
		/* A += 1 */
		s[i] = new_stmt(BPF_ALU|BPF_ADD|BPF_K);
		s[i]->s.k = 1;
		i++;
		/* A *= 8 */
		s[i] = new_stmt(BPF_ALU|BPF_MUL|BPF_K);
		s[i]->s.k = 8;
		i++;
		/* A += X */
		s[i] = new_stmt(BPF_ALU|BPF_ADD|BPF_X);
		s[i]->s.k = 0;
		i++;
		/* X = A; */
		s[i] = new_stmt(BPF_MISC|BPF_TAX);
		i++;
		/* A = MEM[reg2] */
		s[i] = new_stmt(BPF_LD|BPF_MEM);
		s[i]->s.k = reg2;
		i++;

		/* goto again; (must use BPF_JA for backward jump) */
		s[i] = new_stmt(BPF_JMP|BPF_JA);
		s[i]->s.k = again - i - 1;
		s[i - 1]->s.jf = s[i];
		i++;

		/* fixup */
		for (j = v6start; j <= v6end; j++)
			s[j]->s.jt = s[v6advance];
	} else {
		/* nop */
		s[i] = new_stmt(BPF_ALU|BPF_ADD|BPF_K);
		s[i]->s.k = 0;
		s[fix2]->s.jf = s[i];
		i++;
	}

	/* ahcheck: */
	ahcheck = i;
	/* if (A == IPPROTO_AH) then fall through; else goto end; */
	s[i] = new_stmt(BPF_JMP|BPF_JEQ|BPF_K);
	s[i]->s.jt = NULL;	/*later*/
	s[i]->s.jf = NULL;	/*later*/
	s[i]->s.k = IPPROTO_AH;
	if (fix3)
		s[fix3]->s.jf = s[ahcheck];
	fix4 = i;
	i++;

	/*
	 * in short,
	 * A = P[X];
	 * X = X + (P[X + 1] + 2) * 4;
	 */
	/* A = X */
	s[i - 1]->s.jt = s[i] = new_stmt(BPF_MISC|BPF_TXA);
	i++;
	/* A = P[X + packet head]; */
	s[i] = new_stmt(BPF_LD|BPF_IND|BPF_B);
	s[i]->s.k = off_macpl + off_nl;
	i++;
	/* MEM[reg2] = A */
	s[i] = new_stmt(BPF_ST);
	s[i]->s.k = reg2;
	i++;
	/* A = X */
	s[i - 1]->s.jt = s[i] = new_stmt(BPF_MISC|BPF_TXA);
	i++;
	/* A += 1 */
	s[i] = new_stmt(BPF_ALU|BPF_ADD|BPF_K);
	s[i]->s.k = 1;
	i++;
	/* X = A */
	s[i] = new_stmt(BPF_MISC|BPF_TAX);
	i++;
	/* A = P[X + packet head] */
	s[i] = new_stmt(BPF_LD|BPF_IND|BPF_B);
	s[i]->s.k = off_macpl + off_nl;
	i++;
	/* A += 2 */
	s[i] = new_stmt(BPF_ALU|BPF_ADD|BPF_K);
	s[i]->s.k = 2;
	i++;
	/* A *= 4 */
	s[i] = new_stmt(BPF_ALU|BPF_MUL|BPF_K);
	s[i]->s.k = 4;
	i++;
	/* X = A; */
	s[i] = new_stmt(BPF_MISC|BPF_TAX);
	i++;
	/* A = MEM[reg2] */
	s[i] = new_stmt(BPF_LD|BPF_MEM);
	s[i]->s.k = reg2;
	i++;

	/* goto again; (must use BPF_JA for backward jump) */
	s[i] = new_stmt(BPF_JMP|BPF_JA);
	s[i]->s.k = again - i - 1;
	i++;

	/* end: nop */
	end = i;
	s[i] = new_stmt(BPF_ALU|BPF_ADD|BPF_K);
	s[i]->s.k = 0;
	s[fix2]->s.jt = s[end];
	s[fix4]->s.jf = s[end];
	s[fix5]->s.jt = s[end];
	i++;

	/*
	 * make slist chain
	 */
	max = i;
	for (i = 0; i < max - 1; i++)
		s[i]->next = s[i + 1];
	s[max - 1]->next = NULL;

	/*
	 * emit final check
	 */
	b = new_block(JMP(BPF_JEQ));
	b->stmts = s[1];	/*remember, s[0] is dummy*/
	b->s.k = v;

	free_reg(reg2);

	gen_and(b0, b);
	return b;
#endif
}

static struct block *
gen_check_802_11_data_frame()
{
	struct slist *s;
	struct block *b0, *b1;

	/*
	 * A data frame has the 0x08 bit (b3) in the frame control field set
	 * and the 0x04 bit (b2) clear.
	 */
	s = gen_load_a(OR_LINK, 0, BPF_B);
	b0 = new_block(JMP(BPF_JSET));
	b0->s.k = 0x08;
	b0->stmts = s;
	
	s = gen_load_a(OR_LINK, 0, BPF_B);
	b1 = new_block(JMP(BPF_JSET));
	b1->s.k = 0x04;
	b1->stmts = s;
	gen_not(b1);

	gen_and(b1, b0);

	return b0;
}

/*
 * Generate code that checks whether the packet is a packet for protocol
 * <proto> and whether the type field in that protocol's header has
 * the value <v>, e.g. if <proto> is Q_IP, it checks whether it's an
 * IP packet and checks the protocol number in the IP header against <v>.
 *
 * If <proto> is Q_DEFAULT, i.e. just "proto" was specified, it checks
 * against Q_IP and Q_IPV6.
 */
static struct block *
gen_proto(v, proto, dir)
	int v;
	int proto;
	int dir;
{
	struct block *b0, *b1;
#ifndef CHASE_CHAIN
	struct block *b2;
#endif

	if (dir != Q_DEFAULT)
		bpf_error("direction applied to 'proto'");

	switch (proto) {
	case Q_DEFAULT:
		b0 = gen_proto(v, Q_IP, dir);
		b1 = gen_proto(v, Q_IPV6, dir);
		gen_or(b0, b1);
		return b1;

	case Q_IP:
		/*
		 * For FDDI, RFC 1188 says that SNAP encapsulation is used,
		 * not LLC encapsulation with LLCSAP_IP.
		 *
		 * For IEEE 802 networks - which includes 802.5 token ring
		 * (which is what DLT_IEEE802 means) and 802.11 - RFC 1042
		 * says that SNAP encapsulation is used, not LLC encapsulation
		 * with LLCSAP_IP.
		 *
		 * For LLC-encapsulated ATM/"Classical IP", RFC 1483 and
		 * RFC 2225 say that SNAP encapsulation is used, not LLC
		 * encapsulation with LLCSAP_IP.
		 *
		 * So we always check for ETHERTYPE_IP.
		 */
		b0 = gen_linktype(ETHERTYPE_IP);
#ifndef CHASE_CHAIN
		b1 = gen_cmp(OR_NET, 9, BPF_B, (bpf_int32)v);
#else
		b1 = gen_protochain(v, Q_IP);
#endif
		gen_and(b0, b1);
		return b1;

	case Q_ISO:
		switch (linktype) {

		case DLT_FRELAY:
			/*
			 * Frame Relay packets typically have an OSI
			 * NLPID at the beginning; "gen_linktype(LLCSAP_ISONS)"
			 * generates code to check for all the OSI
			 * NLPIDs, so calling it and then adding a check
			 * for the particular NLPID for which we're
			 * looking is bogus, as we can just check for
			 * the NLPID.
			 *
			 * What we check for is the NLPID and a frame
			 * control field value of UI, i.e. 0x03 followed
			 * by the NLPID.
			 *
			 * XXX - assumes a 2-byte Frame Relay header with
			 * DLCI and flags.  What if the address is longer?
			 *
			 * XXX - what about SNAP-encapsulated frames?
			 */
			return gen_cmp(OR_LINK, 2, BPF_H, (0x03<<8) | v);
			/*NOTREACHED*/
			break;

		case DLT_C_HDLC:
			/*
			 * Cisco uses an Ethertype lookalike - for OSI,
			 * it's 0xfefe.
			 */
			b0 = gen_linktype(LLCSAP_ISONS<<8 | LLCSAP_ISONS);
			/* OSI in C-HDLC is stuffed with a fudge byte */
			b1 = gen_cmp(OR_NET_NOSNAP, 1, BPF_B, (long)v);
			gen_and(b0, b1);
			return b1;

		default:
			b0 = gen_linktype(LLCSAP_ISONS);
			b1 = gen_cmp(OR_NET_NOSNAP, 0, BPF_B, (long)v);
			gen_and(b0, b1);
			return b1;
		}

	case Q_ISIS:
		b0 = gen_proto(ISO10589_ISIS, Q_ISO, Q_DEFAULT);
		/*
		 * 4 is the offset of the PDU type relative to the IS-IS
		 * header.
		 */
		b1 = gen_cmp(OR_NET_NOSNAP, 4, BPF_B, (long)v);
		gen_and(b0, b1);
		return b1;

	case Q_ARP:
		bpf_error("arp does not encapsulate another protocol");
		/* NOTREACHED */

	case Q_RARP:
		bpf_error("rarp does not encapsulate another protocol");
		/* NOTREACHED */

	case Q_ATALK:
		bpf_error("atalk encapsulation is not specifiable");
		/* NOTREACHED */

	case Q_DECNET:
		bpf_error("decnet encapsulation is not specifiable");
		/* NOTREACHED */

	case Q_SCA:
		bpf_error("sca does not encapsulate another protocol");
		/* NOTREACHED */

	case Q_LAT:
		bpf_error("lat does not encapsulate another protocol");
		/* NOTREACHED */

	case Q_MOPRC:
		bpf_error("moprc does not encapsulate another protocol");
		/* NOTREACHED */

	case Q_MOPDL:
		bpf_error("mopdl does not encapsulate another protocol");
		/* NOTREACHED */

	case Q_LINK:
		return gen_linktype(v);

	case Q_UDP:
		bpf_error("'udp proto' is bogus");
		/* NOTREACHED */

	case Q_TCP:
		bpf_error("'tcp proto' is bogus");
		/* NOTREACHED */

	case Q_SCTP:
		bpf_error("'sctp proto' is bogus");
		/* NOTREACHED */

	case Q_ICMP:
		bpf_error("'icmp proto' is bogus");
		/* NOTREACHED */

	case Q_IGMP:
		bpf_error("'igmp proto' is bogus");
		/* NOTREACHED */

	case Q_IGRP:
		bpf_error("'igrp proto' is bogus");
		/* NOTREACHED */

	case Q_PIM:
		bpf_error("'pim proto' is bogus");
		/* NOTREACHED */

	case Q_VRRP:
		bpf_error("'vrrp proto' is bogus");
		/* NOTREACHED */

	case Q_CARP:
		bpf_error("'carp proto' is bogus");
		/* NOTREACHED */

	case Q_IPV6:
		b0 = gen_linktype(ETHERTYPE_IPV6);
#ifndef CHASE_CHAIN
		/*
		 * Also check for a fragment header before the final
		 * header.
		 */
		b2 = gen_cmp(OR_NET, 6, BPF_B, IPPROTO_FRAGMENT);
		b1 = gen_cmp(OR_NET, 40, BPF_B, (bpf_int32)v);
		gen_and(b2, b1);
		b2 = gen_cmp(OR_NET, 6, BPF_B, (bpf_int32)v);
		gen_or(b2, b1);
#else
		b1 = gen_protochain(v, Q_IPV6);
#endif
		gen_and(b0, b1);
		return b1;

	case Q_ICMPV6:
		bpf_error("'icmp6 proto' is bogus");

	case Q_AH:
		bpf_error("'ah proto' is bogus");

	case Q_ESP:
		bpf_error("'ah proto' is bogus");

	case Q_STP:
		bpf_error("'stp proto' is bogus");

	case Q_IPX:
		bpf_error("'ipx proto' is bogus");

	case Q_NETBEUI:
		bpf_error("'netbeui proto' is bogus");

	case Q_RADIO:
		bpf_error("'radio proto' is bogus");

	default:
		abort();
		/* NOTREACHED */
	}
	/* NOTREACHED */
}

struct block *
gen_scode(name, q)
	register const char *name;
	struct qual q;
{
	int proto = q.proto;
	int dir = q.dir;
	int tproto;
	u_char *eaddr;
	bpf_u_int32 mask, addr;
#ifndef INET6
	bpf_u_int32 **alist;
#else
	int tproto6;
	struct sockaddr_in *sin4;
	struct sockaddr_in6 *sin6;
	struct addrinfo *res, *res0;
	struct in6_addr mask128;
#endif /*INET6*/
	struct block *b, *tmp;
	int port, real_proto;
	int port1, port2;

	switch (q.addr) {

	case Q_NET:
		addr = pcap_nametonetaddr(name);
		if (addr == 0)
			bpf_error("unknown network '%s'", name);
		/* Left justify network addr and calculate its network mask */
		mask = 0xffffffff;
		while (addr && (addr & 0xff000000) == 0) {
			addr <<= 8;
			mask <<= 8;
		}
		return gen_host(addr, mask, proto, dir, q.addr);

	case Q_DEFAULT:
	case Q_HOST:
		if (proto == Q_LINK) {
			switch (linktype) {

			case DLT_EN10MB:
			case DLT_NETANALYZER:
			case DLT_NETANALYZER_TRANSPARENT:
				eaddr = pcap_ether_hostton(name);
				if (eaddr == NULL)
					bpf_error(
					    "unknown ether host '%s'", name);
				b = gen_ehostop(eaddr, dir);
				free(eaddr);
				return b;

			case DLT_FDDI:
				eaddr = pcap_ether_hostton(name);
				if (eaddr == NULL)
					bpf_error(
					    "unknown FDDI host '%s'", name);
				b = gen_fhostop(eaddr, dir);
				free(eaddr);
				return b;

			case DLT_IEEE802:
				eaddr = pcap_ether_hostton(name);
				if (eaddr == NULL)
					bpf_error(
					    "unknown token ring host '%s'", name);
				b = gen_thostop(eaddr, dir);
				free(eaddr);
				return b;

			case DLT_IEEE802_11:
			case DLT_PRISM_HEADER:
			case DLT_IEEE802_11_RADIO_AVS:
			case DLT_IEEE802_11_RADIO:
			case DLT_PPI:
				eaddr = pcap_ether_hostton(name);
				if (eaddr == NULL)
					bpf_error(
					    "unknown 802.11 host '%s'", name);
				b = gen_wlanhostop(eaddr, dir);
				free(eaddr);
				return b;

			case DLT_IP_OVER_FC:
				eaddr = pcap_ether_hostton(name);
				if (eaddr == NULL)
					bpf_error(
					    "unknown Fibre Channel host '%s'", name);
				b = gen_ipfchostop(eaddr, dir);
				free(eaddr);
				return b;

			case DLT_SUNATM:
				if (!is_lane)
					break;

				/*
				 * Check that the packet doesn't begin
				 * with an LE Control marker.  (We've
				 * already generated a test for LANE.)
				 */
				tmp = gen_cmp(OR_LINK, SUNATM_PKT_BEGIN_POS,
				    BPF_H, 0xFF00);
				gen_not(tmp);

				eaddr = pcap_ether_hostton(name);
				if (eaddr == NULL)
					bpf_error(
					    "unknown ether host '%s'", name);
				b = gen_ehostop(eaddr, dir);
				gen_and(tmp, b);
				free(eaddr);
				return b;
			}

			bpf_error("only ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel supports link-level host name");
		} else if (proto == Q_DECNET) {
			unsigned short dn_addr = __pcap_nametodnaddr(name);
			/*
			 * I don't think DECNET hosts can be multihomed, so
			 * there is no need to build up a list of addresses
			 */
			return (gen_host(dn_addr, 0, proto, dir, q.addr));
		} else {
#ifndef INET6
			alist = pcap_nametoaddr(name);
			if (alist == NULL || *alist == NULL)
				bpf_error("unknown host '%s'", name);
			tproto = proto;
			if (off_linktype == (u_int)-1 && tproto == Q_DEFAULT)
				tproto = Q_IP;
			b = gen_host(**alist++, 0xffffffff, tproto, dir, q.addr);
			while (*alist) {
				tmp = gen_host(**alist++, 0xffffffff,
					       tproto, dir, q.addr);
				gen_or(b, tmp);
				b = tmp;
			}
			return b;
#else
			memset(&mask128, 0xff, sizeof(mask128));
			res0 = res = pcap_nametoaddrinfo(name);
			if (res == NULL)
				bpf_error("unknown host '%s'", name);
			ai = res;
			b = tmp = NULL;
			tproto = tproto6 = proto;
			if (off_linktype == -1 && tproto == Q_DEFAULT) {
				tproto = Q_IP;
				tproto6 = Q_IPV6;
			}
			for (res = res0; res; res = res->ai_next) {
				switch (res->ai_family) {
				case AF_INET:
					if (tproto == Q_IPV6)
						continue;

					sin4 = (struct sockaddr_in *)
						res->ai_addr;
					tmp = gen_host(ntohl(sin4->sin_addr.s_addr),
						0xffffffff, tproto, dir, q.addr);
					break;
				case AF_INET6:
					if (tproto6 == Q_IP)
						continue;

					sin6 = (struct sockaddr_in6 *)
						res->ai_addr;
					tmp = gen_host6(&sin6->sin6_addr,
						&mask128, tproto6, dir, q.addr);
					break;
				default:
					continue;
				}
				if (b)
					gen_or(b, tmp);
				b = tmp;
			}
			ai = NULL;
			freeaddrinfo(res0);
			if (b == NULL) {
				bpf_error("unknown host '%s'%s", name,
				    (proto == Q_DEFAULT)
					? ""
					: " for specified address family");
			}
			return b;
#endif /*INET6*/
		}

	case Q_PORT:
		if (proto != Q_DEFAULT &&
		    proto != Q_UDP && proto != Q_TCP && proto != Q_SCTP)
			bpf_error("illegal qualifier of 'port'");
		if (pcap_nametoport(name, &port, &real_proto) == 0)
			bpf_error("unknown port '%s'", name);
		if (proto == Q_UDP) {
			if (real_proto == IPPROTO_TCP)
				bpf_error("port '%s' is tcp", name);
			else if (real_proto == IPPROTO_SCTP)
				bpf_error("port '%s' is sctp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_UDP;
		}
		if (proto == Q_TCP) {
			if (real_proto == IPPROTO_UDP)
				bpf_error("port '%s' is udp", name);

			else if (real_proto == IPPROTO_SCTP)
				bpf_error("port '%s' is sctp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_TCP;
		}
		if (proto == Q_SCTP) {
			if (real_proto == IPPROTO_UDP)
				bpf_error("port '%s' is udp", name);

			else if (real_proto == IPPROTO_TCP)
				bpf_error("port '%s' is tcp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_SCTP;
		}
		if (port < 0)
			bpf_error("illegal port number %d < 0", port);
		if (port > 65535)
			bpf_error("illegal port number %d > 65535", port);
		b = gen_port(port, real_proto, dir);
		gen_or(gen_port6(port, real_proto, dir), b);
		return b;

	case Q_PORTRANGE:
		if (proto != Q_DEFAULT &&
		    proto != Q_UDP && proto != Q_TCP && proto != Q_SCTP)
			bpf_error("illegal qualifier of 'portrange'");
		if (pcap_nametoportrange(name, &port1, &port2, &real_proto) == 0) 
			bpf_error("unknown port in range '%s'", name);
		if (proto == Q_UDP) {
			if (real_proto == IPPROTO_TCP)
				bpf_error("port in range '%s' is tcp", name);
			else if (real_proto == IPPROTO_SCTP)
				bpf_error("port in range '%s' is sctp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_UDP;
		}
		if (proto == Q_TCP) {
			if (real_proto == IPPROTO_UDP)
				bpf_error("port in range '%s' is udp", name);
			else if (real_proto == IPPROTO_SCTP)
				bpf_error("port in range '%s' is sctp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_TCP;
		}
		if (proto == Q_SCTP) {
			if (real_proto == IPPROTO_UDP)
				bpf_error("port in range '%s' is udp", name);
			else if (real_proto == IPPROTO_TCP)
				bpf_error("port in range '%s' is tcp", name);
			else
				/* override PROTO_UNDEF */
				real_proto = IPPROTO_SCTP;	
		}
		if (port1 < 0)
			bpf_error("illegal port number %d < 0", port1);
		if (port1 > 65535)
			bpf_error("illegal port number %d > 65535", port1);
		if (port2 < 0)
			bpf_error("illegal port number %d < 0", port2);
		if (port2 > 65535)
			bpf_error("illegal port number %d > 65535", port2);

		b = gen_portrange(port1, port2, real_proto, dir);
		gen_or(gen_portrange6(port1, port2, real_proto, dir), b);
		return b;

	case Q_GATEWAY:
#ifndef INET6
		eaddr = pcap_ether_hostton(name);
		if (eaddr == NULL)
			bpf_error("unknown ether host: %s", name);

		alist = pcap_nametoaddr(name);
		if (alist == NULL || *alist == NULL)
			bpf_error("unknown host '%s'", name);
		b = gen_gateway(eaddr, alist, proto, dir);
		free(eaddr);
		return b;
#else
		bpf_error("'gateway' not supported in this configuration");
#endif /*INET6*/

	case Q_PROTO:
		real_proto = lookup_proto(name, proto);
		if (real_proto >= 0)
			return gen_proto(real_proto, proto, dir);
		else
			bpf_error("unknown protocol: %s", name);

	case Q_PROTOCHAIN:
		real_proto = lookup_proto(name, proto);
		if (real_proto >= 0)
			return gen_protochain(real_proto, proto, dir);
		else
			bpf_error("unknown protocol: %s", name);

	case Q_UNDEF:
		syntax();
		/* NOTREACHED */
	}
	abort();
	/* NOTREACHED */
}

struct block *
gen_mcode(s1, s2, masklen, q)
	register const char *s1, *s2;
	register int masklen;
	struct qual q;
{
	register int nlen, mlen;
	bpf_u_int32 n, m;

	nlen = __pcap_atoin(s1, &n);
	/* Promote short ipaddr */
	n <<= 32 - nlen;

	if (s2 != NULL) {
		mlen = __pcap_atoin(s2, &m);
		/* Promote short ipaddr */
		m <<= 32 - mlen;
		if ((n & ~m) != 0)
			bpf_error("non-network bits set in \"%s mask %s\"",
			    s1, s2);
	} else {
		/* Convert mask len to mask */
		if (masklen > 32)
			bpf_error("mask length must be <= 32");
		if (masklen == 0) {
			/*
			 * X << 32 is not guaranteed by C to be 0; it's
			 * undefined.
			 */
			m = 0;
		} else
			m = 0xffffffff << (32 - masklen);
		if ((n & ~m) != 0)
			bpf_error("non-network bits set in \"%s/%d\"",
			    s1, masklen);
	}

	switch (q.addr) {

	case Q_NET:
		return gen_host(n, m, q.proto, q.dir, q.addr);

	default:
		bpf_error("Mask syntax for networks only");
		/* NOTREACHED */
	}
	/* NOTREACHED */
	return NULL;
}

struct block *
gen_ncode(s, v, q)
	register const char *s;
	bpf_u_int32 v;
	struct qual q;
{
	bpf_u_int32 mask;
	int proto = q.proto;
	int dir = q.dir;
	register int vlen;

	if (s == NULL)
		vlen = 32;
	else if (q.proto == Q_DECNET)
		vlen = __pcap_atodn(s, &v);
	else
		vlen = __pcap_atoin(s, &v);

	switch (q.addr) {

	case Q_DEFAULT:
	case Q_HOST:
	case Q_NET:
		if (proto == Q_DECNET)
			return gen_host(v, 0, proto, dir, q.addr);
		else if (proto == Q_LINK) {
			bpf_error("illegal link layer address");
		} else {
			mask = 0xffffffff;
			if (s == NULL && q.addr == Q_NET) {
				/* Promote short net number */
				while (v && (v & 0xff000000) == 0) {
					v <<= 8;
					mask <<= 8;
				}
			} else {
				/* Promote short ipaddr */
				v <<= 32 - vlen;
				mask <<= 32 - vlen;
			}
			return gen_host(v, mask, proto, dir, q.addr);
		}

	case Q_PORT:
		if (proto == Q_UDP)
			proto = IPPROTO_UDP;
		else if (proto == Q_TCP)
			proto = IPPROTO_TCP;
		else if (proto == Q_SCTP)
			proto = IPPROTO_SCTP;
		else if (proto == Q_DEFAULT)
			proto = PROTO_UNDEF;
		else
			bpf_error("illegal qualifier of 'port'");

		if (v > 65535)
			bpf_error("illegal port number %u > 65535", v);

	    {
		struct block *b;
		b = gen_port((int)v, proto, dir);
		gen_or(gen_port6((int)v, proto, dir), b);
		return b;
	    }

	case Q_PORTRANGE:
		if (proto == Q_UDP)
			proto = IPPROTO_UDP;
		else if (proto == Q_TCP)
			proto = IPPROTO_TCP;
		else if (proto == Q_SCTP)
			proto = IPPROTO_SCTP;
		else if (proto == Q_DEFAULT)
			proto = PROTO_UNDEF;
		else
			bpf_error("illegal qualifier of 'portrange'");

		if (v > 65535)
			bpf_error("illegal port number %u > 65535", v);

	    {
		struct block *b;
		b = gen_portrange((int)v, (int)v, proto, dir);
		gen_or(gen_portrange6((int)v, (int)v, proto, dir), b);
		return b;
	    }

	case Q_GATEWAY:
		bpf_error("'gateway' requires a name");
		/* NOTREACHED */

	case Q_PROTO:
		return gen_proto((int)v, proto, dir);

	case Q_PROTOCHAIN:
		return gen_protochain((int)v, proto, dir);

	case Q_UNDEF:
		syntax();
		/* NOTREACHED */

	default:
		abort();
		/* NOTREACHED */
	}
	/* NOTREACHED */
}

#ifdef INET6
struct block *
gen_mcode6(s1, s2, masklen, q)
	register const char *s1, *s2;
	register int masklen;
	struct qual q;
{
	struct addrinfo *res;
	struct in6_addr *addr;
	struct in6_addr mask;
	struct block *b;
	u_int32_t *a, *m;

	if (s2)
		bpf_error("no mask %s supported", s2);

	res = pcap_nametoaddrinfo(s1);
	if (!res)
		bpf_error("invalid ip6 address %s", s1);
	ai = res;
	if (res->ai_next)
		bpf_error("%s resolved to multiple address", s1);
	addr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;

	if (sizeof(mask) * 8 < masklen)
		bpf_error("mask length must be <= %u", (unsigned int)(sizeof(mask) * 8));
	memset(&mask, 0, sizeof(mask));
	memset(&mask, 0xff, masklen / 8);
	if (masklen % 8) {
		mask.s6_addr[masklen / 8] =
			(0xff << (8 - masklen % 8)) & 0xff;
	}

	a = (u_int32_t *)addr;
	m = (u_int32_t *)&mask;
	if ((a[0] & ~m[0]) || (a[1] & ~m[1])
	 || (a[2] & ~m[2]) || (a[3] & ~m[3])) {
		bpf_error("non-network bits set in \"%s/%d\"", s1, masklen);
	}

	switch (q.addr) {

	case Q_DEFAULT:
	case Q_HOST:
		if (masklen != 128)
			bpf_error("Mask syntax for networks only");
		/* FALLTHROUGH */

	case Q_NET:
		b = gen_host6(addr, &mask, q.proto, q.dir, q.addr);
		ai = NULL;
		freeaddrinfo(res);
		return b;

	default:
		bpf_error("invalid qualifier against IPv6 address");
		/* NOTREACHED */
	}
	return NULL;
}
#endif /*INET6*/

struct block *
gen_ecode(eaddr, q)
	register const u_char *eaddr;
	struct qual q;
{
	struct block *b, *tmp;

	if ((q.addr == Q_HOST || q.addr == Q_DEFAULT) && q.proto == Q_LINK) {
		switch (linktype) {
		case DLT_EN10MB:
		case DLT_NETANALYZER:
		case DLT_NETANALYZER_TRANSPARENT:
			return gen_ehostop(eaddr, (int)q.dir);
		case DLT_FDDI:
			return gen_fhostop(eaddr, (int)q.dir);
		case DLT_IEEE802:
			return gen_thostop(eaddr, (int)q.dir);
		case DLT_IEEE802_11:
		case DLT_PRISM_HEADER:
		case DLT_IEEE802_11_RADIO_AVS:
		case DLT_IEEE802_11_RADIO:
		case DLT_PPI:
			return gen_wlanhostop(eaddr, (int)q.dir);
		case DLT_SUNATM:
			if (is_lane) {
				/*
				 * Check that the packet doesn't begin with an
				 * LE Control marker.  (We've already generated
				 * a test for LANE.)
				 */
				tmp = gen_cmp(OR_LINK, SUNATM_PKT_BEGIN_POS, BPF_H,
					0xFF00);
				gen_not(tmp);

				/*
				 * Now check the MAC address.
				 */
				b = gen_ehostop(eaddr, (int)q.dir);
				gen_and(tmp, b);
				return b;
			}
			break;
		case DLT_IP_OVER_FC:
			return gen_ipfchostop(eaddr, (int)q.dir);
		default:
			bpf_error("ethernet addresses supported only on ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel");
			break;
		}
	}
	bpf_error("ethernet address used in non-ether expression");
	/* NOTREACHED */
	return NULL;
}

void
sappend(s0, s1)
	struct slist *s0, *s1;
{
	/*
	 * This is definitely not the best way to do this, but the
	 * lists will rarely get long.
	 */
	while (s0->next)
		s0 = s0->next;
	s0->next = s1;
}

static struct slist *
xfer_to_x(a)
	struct arth *a;
{
	struct slist *s;

	s = new_stmt(BPF_LDX|BPF_MEM);
	s->s.k = a->regno;
	return s;
}

static struct slist *
xfer_to_a(a)
	struct arth *a;
{
	struct slist *s;

	s = new_stmt(BPF_LD|BPF_MEM);
	s->s.k = a->regno;
	return s;
}

/*
 * Modify "index" to use the value stored into its register as an
 * offset relative to the beginning of the header for the protocol
 * "proto", and allocate a register and put an item "size" bytes long
 * (1, 2, or 4) at that offset into that register, making it the register
 * for "index".
 */
struct arth *
gen_load(proto, inst, size)
	int proto;
	struct arth *inst;
	int size;
{
	struct slist *s, *tmp;
	struct block *b;
	int regno = alloc_reg();

	free_reg(inst->regno);
	switch (size) {

	default:
		bpf_error("data size must be 1, 2, or 4");

	case 1:
		size = BPF_B;
		break;

	case 2:
		size = BPF_H;
		break;

	case 4:
		size = BPF_W;
		break;
	}
	switch (proto) {
	default:
		bpf_error("unsupported index operation");

	case Q_RADIO:
		/*
		 * The offset is relative to the beginning of the packet
		 * data, if we have a radio header.  (If we don't, this
		 * is an error.)
		 */
		if (linktype != DLT_IEEE802_11_RADIO_AVS &&
		    linktype != DLT_IEEE802_11_RADIO &&
		    linktype != DLT_PRISM_HEADER)
			bpf_error("radio information not present in capture");

		/*
		 * Load into the X register the offset computed into the
		 * register specified by "index".
		 */
		s = xfer_to_x(inst);

		/*
		 * Load the item at that offset.
		 */
		tmp = new_stmt(BPF_LD|BPF_IND|size);
		sappend(s, tmp);
		sappend(inst->s, s);
		break;

	case Q_LINK:
		/*
		 * The offset is relative to the beginning of
		 * the link-layer header.
		 *
		 * XXX - what about ATM LANE?  Should the index be
		 * relative to the beginning of the AAL5 frame, so
		 * that 0 refers to the beginning of the LE Control
		 * field, or relative to the beginning of the LAN
		 * frame, so that 0 refers, for Ethernet LANE, to
		 * the beginning of the destination address?
		 */
		s = gen_llprefixlen();

		/*
		 * If "s" is non-null, it has code to arrange that the
		 * X register contains the length of the prefix preceding
		 * the link-layer header.  Add to it the offset computed
		 * into the register specified by "index", and move that
		 * into the X register.  Otherwise, just load into the X
		 * register the offset computed into the register specified
		 * by "index".
		 */
		if (s != NULL) {
			sappend(s, xfer_to_a(inst));
			sappend(s, new_stmt(BPF_ALU|BPF_ADD|BPF_X));
			sappend(s, new_stmt(BPF_MISC|BPF_TAX));
		} else
			s = xfer_to_x(inst);

		/*
		 * Load the item at the sum of the offset we've put in the
		 * X register and the offset of the start of the link
		 * layer header (which is 0 if the radio header is
		 * variable-length; that header length is what we put
		 * into the X register and then added to the index).
		 */
		tmp = new_stmt(BPF_LD|BPF_IND|size);
		tmp->s.k = off_ll;
		sappend(s, tmp);
		sappend(inst->s, s);
		break;

	case Q_IP:
	case Q_ARP:
	case Q_RARP:
	case Q_ATALK:
	case Q_DECNET:
	case Q_SCA:
	case Q_LAT:
	case Q_MOPRC:
	case Q_MOPDL:
	case Q_IPV6:
		/*
		 * The offset is relative to the beginning of
		 * the network-layer header.
		 * XXX - are there any cases where we want
		 * off_nl_nosnap?
		 */
		s = gen_off_macpl();

		/*
		 * If "s" is non-null, it has code to arrange that the
		 * X register contains the offset of the MAC-layer
		 * payload.  Add to it the offset computed into the
		 * register specified by "index", and move that into
		 * the X register.  Otherwise, just load into the X
		 * register the offset computed into the register specified
		 * by "index".
		 */
		if (s != NULL) {
			sappend(s, xfer_to_a(inst));
			sappend(s, new_stmt(BPF_ALU|BPF_ADD|BPF_X));
			sappend(s, new_stmt(BPF_MISC|BPF_TAX));
		} else
			s = xfer_to_x(inst);

		/*
		 * Load the item at the sum of the offset we've put in the
		 * X register, the offset of the start of the network
		 * layer header from the beginning of the MAC-layer
		 * payload, and the purported offset of the start of the
		 * MAC-layer payload (which might be 0 if there's a
		 * variable-length prefix before the link-layer header
		 * or the link-layer header itself is variable-length;
		 * the variable-length offset of the start of the
		 * MAC-layer payload is what we put into the X register
		 * and then added to the index).
		 */
		tmp = new_stmt(BPF_LD|BPF_IND|size);
		tmp->s.k = off_macpl + off_nl;
		sappend(s, tmp);
		sappend(inst->s, s);

		/*
		 * Do the computation only if the packet contains
		 * the protocol in question.
		 */
		b = gen_proto_abbrev(proto);
		if (inst->b)
			gen_and(inst->b, b);
		inst->b = b;
		break;

	case Q_SCTP:
	case Q_TCP:
	case Q_UDP:
	case Q_ICMP:
	case Q_IGMP:
	case Q_IGRP:
	case Q_PIM:
	case Q_VRRP:
	case Q_CARP:
		/*
		 * The offset is relative to the beginning of
		 * the transport-layer header.
		 *
		 * Load the X register with the length of the IPv4 header
		 * (plus the offset of the link-layer header, if it's
		 * a variable-length header), in bytes.
		 *
		 * XXX - are there any cases where we want
		 * off_nl_nosnap?
		 * XXX - we should, if we're built with
		 * IPv6 support, generate code to load either
		 * IPv4, IPv6, or both, as appropriate.
		 */
		s = gen_loadx_iphdrlen();

		/*
		 * The X register now contains the sum of the length
		 * of any variable-length header preceding the link-layer
		 * header, any variable-length link-layer header, and the
		 * length of the network-layer header.
		 *
		 * Load into the A register the offset relative to
		 * the beginning of the transport layer header,
		 * add the X register to that, move that to the
		 * X register, and load with an offset from the
		 * X register equal to the offset of the network
		 * layer header relative to the beginning of
		 * the MAC-layer payload plus the fixed-length
		 * portion of the offset of the MAC-layer payload
		 * from the beginning of the raw packet data.
		 */
		sappend(s, xfer_to_a(inst));
		sappend(s, new_stmt(BPF_ALU|BPF_ADD|BPF_X));
		sappend(s, new_stmt(BPF_MISC|BPF_TAX));
		sappend(s, tmp = new_stmt(BPF_LD|BPF_IND|size));
		tmp->s.k = off_macpl + off_nl;
		sappend(inst->s, s);

		/*
		 * Do the computation only if the packet contains
		 * the protocol in question - which is true only
		 * if this is an IP datagram and is the first or
		 * only fragment of that datagram.
		 */
		gen_and(gen_proto_abbrev(proto), b = gen_ipfrag());
		if (inst->b)
			gen_and(inst->b, b);
		gen_and(gen_proto_abbrev(Q_IP), b);
		inst->b = b;
		break;
	case Q_ICMPV6:
		bpf_error("IPv6 upper-layer protocol is not supported by proto[x]");
		/*NOTREACHED*/
	}
	inst->regno = regno;
	s = new_stmt(BPF_ST);
	s->s.k = regno;
	sappend(inst->s, s);

	return inst;
}

struct block *
gen_relation(code, a0, a1, reversed)
	int code;
	struct arth *a0, *a1;
	int reversed;
{
	struct slist *s0, *s1, *s2;
	struct block *b, *tmp;

	s0 = xfer_to_x(a1);
	s1 = xfer_to_a(a0);
	if (code == BPF_JEQ) {
		s2 = new_stmt(BPF_ALU|BPF_SUB|BPF_X);
		b = new_block(JMP(code));
		sappend(s1, s2);
	}
	else
		b = new_block(BPF_JMP|code|BPF_X);
	if (reversed)
		gen_not(b);

	sappend(s0, s1);
	sappend(a1->s, s0);
	sappend(a0->s, a1->s);

	b->stmts = a0->s;

	free_reg(a0->regno);
	free_reg(a1->regno);

	/* 'and' together protocol checks */
	if (a0->b) {
		if (a1->b) {
			gen_and(a0->b, tmp = a1->b);
		}
		else
			tmp = a0->b;
	} else
		tmp = a1->b;

	if (tmp)
		gen_and(tmp, b);

	return b;
}

struct arth *
gen_loadlen()
{
	int regno = alloc_reg();
	struct arth *a = (struct arth *)newchunk(sizeof(*a));
	struct slist *s;

	s = new_stmt(BPF_LD|BPF_LEN);
	s->next = new_stmt(BPF_ST);
	s->next->s.k = regno;
	a->s = s;
	a->regno = regno;

	return a;
}

struct arth *
gen_loadi(val)
	int val;
{
	struct arth *a;
	struct slist *s;
	int reg;

	a = (struct arth *)newchunk(sizeof(*a));

	reg = alloc_reg();

	s = new_stmt(BPF_LD|BPF_IMM);
	s->s.k = val;
	s->next = new_stmt(BPF_ST);
	s->next->s.k = reg;
	a->s = s;
	a->regno = reg;

	return a;
}

struct arth *
gen_neg(a)
	struct arth *a;
{
	struct slist *s;

	s = xfer_to_a(a);
	sappend(a->s, s);
	s = new_stmt(BPF_ALU|BPF_NEG);
	s->s.k = 0;
	sappend(a->s, s);
	s = new_stmt(BPF_ST);
	s->s.k = a->regno;
	sappend(a->s, s);

	return a;
}

struct arth *
gen_arth(code, a0, a1)
	int code;
	struct arth *a0, *a1;
{
	struct slist *s0, *s1, *s2;

	s0 = xfer_to_x(a1);
	s1 = xfer_to_a(a0);
	s2 = new_stmt(BPF_ALU|BPF_X|code);

	sappend(s1, s2);
	sappend(s0, s1);
	sappend(a1->s, s0);
	sappend(a0->s, a1->s);

	free_reg(a0->regno);
	free_reg(a1->regno);

	s0 = new_stmt(BPF_ST);
	a0->regno = s0->s.k = alloc_reg();
	sappend(a0->s, s0);

	return a0;
}

/*
 * Here we handle simple allocation of the scratch registers.
 * If too many registers are alloc'd, the allocator punts.
 */
static int regused[BPF_MEMWORDS];
static int curreg;

/*
 * Initialize the table of used registers and the current register.
 */
static void
init_regs()
{
	curreg = 0;
	memset(regused, 0, sizeof regused);
}

/*
 * Return the next free register.
 */
static int
alloc_reg()
{
	int n = BPF_MEMWORDS;

	while (--n >= 0) {
		if (regused[curreg])
			curreg = (curreg + 1) % BPF_MEMWORDS;
		else {
			regused[curreg] = 1;
			return curreg;
		}
	}
	bpf_error("too many registers needed to evaluate expression");
	/* NOTREACHED */
	return 0;
}

/*
 * Return a register to the table so it can
 * be used later.
 */
static void
free_reg(n)
	int n;
{
	regused[n] = 0;
}

static struct block *
gen_len(jmp, n)
	int jmp, n;
{
	struct slist *s;
	struct block *b;

	s = new_stmt(BPF_LD|BPF_LEN);
	b = new_block(JMP(jmp));
	b->stmts = s;
	b->s.k = n;

	return b;
}

struct block *
gen_greater(n)
	int n;
{
	return gen_len(BPF_JGE, n);
}

/*
 * Actually, this is less than or equal.
 */
struct block *
gen_less(n)
	int n;
{
	struct block *b;

	b = gen_len(BPF_JGT, n);
	gen_not(b);

	return b;
}

/*
 * This is for "byte {idx} {op} {val}"; "idx" is treated as relative to
 * the beginning of the link-layer header.
 * XXX - that means you can't test values in the radiotap header, but
 * as that header is difficult if not impossible to parse generally
 * without a loop, that might not be a severe problem.  A new keyword
 * "radio" could be added for that, although what you'd really want
 * would be a way of testing particular radio header values, which
 * would generate code appropriate to the radio header in question.
 */
struct block *
gen_byteop(op, idx, val)
	int op, idx, val;
{
	struct block *b;
	struct slist *s;

	switch (op) {
	default:
		abort();

	case '=':
		return gen_cmp(OR_LINK, (u_int)idx, BPF_B, (bpf_int32)val);

	case '<':
		b = gen_cmp_lt(OR_LINK, (u_int)idx, BPF_B, (bpf_int32)val);
		return b;

	case '>':
		b = gen_cmp_gt(OR_LINK, (u_int)idx, BPF_B, (bpf_int32)val);
		return b;

	case '|':
		s = new_stmt(BPF_ALU|BPF_OR|BPF_K);
		break;

	case '&':
		s = new_stmt(BPF_ALU|BPF_AND|BPF_K);
		break;
	}
	s->s.k = val;
	b = new_block(JMP(BPF_JEQ));
	b->stmts = s;
	gen_not(b);

	return b;
}

static u_char abroadcast[] = { 0x0 };

struct block *
gen_broadcast(proto)
	int proto;
{
	bpf_u_int32 hostmask;
	struct block *b0, *b1, *b2;
	static u_char ebroadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	switch (proto) {

	case Q_DEFAULT:
	case Q_LINK:
		switch (linktype) {
		case DLT_ARCNET:
		case DLT_ARCNET_LINUX:
			return gen_ahostop(abroadcast, Q_DST);
		case DLT_EN10MB:
		case DLT_NETANALYZER:
		case DLT_NETANALYZER_TRANSPARENT:
			return gen_ehostop(ebroadcast, Q_DST);
		case DLT_FDDI:
			return gen_fhostop(ebroadcast, Q_DST);
		case DLT_IEEE802:
			return gen_thostop(ebroadcast, Q_DST);
		case DLT_IEEE802_11:
		case DLT_PRISM_HEADER:
		case DLT_IEEE802_11_RADIO_AVS:
		case DLT_IEEE802_11_RADIO:
		case DLT_PPI:
			return gen_wlanhostop(ebroadcast, Q_DST);
		case DLT_IP_OVER_FC:
			return gen_ipfchostop(ebroadcast, Q_DST);
		case DLT_SUNATM:
			if (is_lane) {
				/*
				 * Check that the packet doesn't begin with an
				 * LE Control marker.  (We've already generated
				 * a test for LANE.)
				 */
				b1 = gen_cmp(OR_LINK, SUNATM_PKT_BEGIN_POS,
				    BPF_H, 0xFF00);
				gen_not(b1);

				/*
				 * Now check the MAC address.
				 */
				b0 = gen_ehostop(ebroadcast, Q_DST);
				gen_and(b1, b0);
				return b0;
			}
			break;
		default:
			bpf_error("not a broadcast link");
		}
		break;

	case Q_IP:
		/*
		 * We treat a netmask of PCAP_NETMASK_UNKNOWN (0xffffffff)
		 * as an indication that we don't know the netmask, and fail
		 * in that case.
		 */
		if (netmask == PCAP_NETMASK_UNKNOWN)
			bpf_error("netmask not known, so 'ip broadcast' not supported");
		b0 = gen_linktype(ETHERTYPE_IP);
		hostmask = ~netmask;
		b1 = gen_mcmp(OR_NET, 16, BPF_W, (bpf_int32)0, hostmask);
		b2 = gen_mcmp(OR_NET, 16, BPF_W,
			      (bpf_int32)(~0 & hostmask), hostmask);
		gen_or(b1, b2);
		gen_and(b0, b2);
		return b2;
	}
	bpf_error("only link-layer/IP broadcast filters supported");
	/* NOTREACHED */
	return NULL;
}

/*
 * Generate code to test the low-order bit of a MAC address (that's
 * the bottom bit of the *first* byte).
 */
static struct block *
gen_mac_multicast(offset)
	int offset;
{
	register struct block *b0;
	register struct slist *s;

	/* link[offset] & 1 != 0 */
	s = gen_load_a(OR_LINK, offset, BPF_B);
	b0 = new_block(JMP(BPF_JSET));
	b0->s.k = 1;
	b0->stmts = s;
	return b0;
}

struct block *
gen_multicast(proto)
	int proto;
{
	register struct block *b0, *b1, *b2;
	register struct slist *s;

	switch (proto) {

	case Q_DEFAULT:
	case Q_LINK:
		switch (linktype) {
		case DLT_ARCNET:
		case DLT_ARCNET_LINUX:
			/* all ARCnet multicasts use the same address */
			return gen_ahostop(abroadcast, Q_DST);
		case DLT_EN10MB:
		case DLT_NETANALYZER:
		case DLT_NETANALYZER_TRANSPARENT:
			/* ether[0] & 1 != 0 */
			return gen_mac_multicast(0);
		case DLT_FDDI:
			/*
			 * XXX TEST THIS: MIGHT NOT PORT PROPERLY XXX
			 *
			 * XXX - was that referring to bit-order issues?
			 */
			/* fddi[1] & 1 != 0 */
			return gen_mac_multicast(1);
		case DLT_IEEE802:
			/* tr[2] & 1 != 0 */
			return gen_mac_multicast(2);
		case DLT_IEEE802_11:
		case DLT_PRISM_HEADER:
		case DLT_IEEE802_11_RADIO_AVS:
		case DLT_IEEE802_11_RADIO:
		case DLT_PPI:
			/*
			 * Oh, yuk.
			 *
			 *	For control frames, there is no DA.
			 *
			 *	For management frames, DA is at an
			 *	offset of 4 from the beginning of
			 *	the packet.
			 *
			 *	For data frames, DA is at an offset
			 *	of 4 from the beginning of the packet
			 *	if To DS is clear and at an offset of
			 *	16 from the beginning of the packet
			 *	if To DS is set.
			 */

			/*
			 * Generate the tests to be done for data frames.
			 *
			 * First, check for To DS set, i.e. "link[1] & 0x01".
			 */
			s = gen_load_a(OR_LINK, 1, BPF_B);
			b1 = new_block(JMP(BPF_JSET));
			b1->s.k = 0x01;	/* To DS */
			b1->stmts = s;

			/*
			 * If To DS is set, the DA is at 16.
			 */
			b0 = gen_mac_multicast(16);
			gen_and(b1, b0);

			/*
			 * Now, check for To DS not set, i.e. check
			 * "!(link[1] & 0x01)".
			 */
			s = gen_load_a(OR_LINK, 1, BPF_B);
			b2 = new_block(JMP(BPF_JSET));
			b2->s.k = 0x01;	/* To DS */
			b2->stmts = s;
			gen_not(b2);

			/*
			 * If To DS is not set, the DA is at 4.
			 */
			b1 = gen_mac_multicast(4);
			gen_and(b2, b1);

			/*
			 * Now OR together the last two checks.  That gives
			 * the complete set of checks for data frames.
			 */
			gen_or(b1, b0);

			/*
			 * Now check for a data frame.
			 * I.e, check "link[0] & 0x08".
			 */
			s = gen_load_a(OR_LINK, 0, BPF_B);
			b1 = new_block(JMP(BPF_JSET));
			b1->s.k = 0x08;
			b1->stmts = s;

			/*
			 * AND that with the checks done for data frames.
			 */
			gen_and(b1, b0);

			/*
			 * If the high-order bit of the type value is 0, this
			 * is a management frame.
			 * I.e, check "!(link[0] & 0x08)".
			 */
			s = gen_load_a(OR_LINK, 0, BPF_B);
			b2 = new_block(JMP(BPF_JSET));
			b2->s.k = 0x08;
			b2->stmts = s;
			gen_not(b2);

			/*
			 * For management frames, the DA is at 4.
			 */
			b1 = gen_mac_multicast(4);
			gen_and(b2, b1);

			/*
			 * OR that with the checks done for data frames.
			 * That gives the checks done for management and
			 * data frames.
			 */
			gen_or(b1, b0);

			/*
			 * If the low-order bit of the type value is 1,
			 * this is either a control frame or a frame
			 * with a reserved type, and thus not a
			 * frame with an SA.
			 *
			 * I.e., check "!(link[0] & 0x04)".
			 */
			s = gen_load_a(OR_LINK, 0, BPF_B);
			b1 = new_block(JMP(BPF_JSET));
			b1->s.k = 0x04;
			b1->stmts = s;
			gen_not(b1);

			/*
			 * AND that with the checks for data and management
			 * frames.
			 */
			gen_and(b1, b0);
			return b0;
		case DLT_IP_OVER_FC:
			b0 = gen_mac_multicast(2);
			return b0;
		case DLT_SUNATM:
			if (is_lane) {
				/*
				 * Check that the packet doesn't begin with an
				 * LE Control marker.  (We've already generated
				 * a test for LANE.)
				 */
				b1 = gen_cmp(OR_LINK, SUNATM_PKT_BEGIN_POS,
				    BPF_H, 0xFF00);
				gen_not(b1);

				/* ether[off_mac] & 1 != 0 */
				b0 = gen_mac_multicast(off_mac);
				gen_and(b1, b0);
				return b0;
			}
			break;
		default:
			break;
		}
		/* Link not known to support multicasts */
		break;

	case Q_IP:
		b0 = gen_linktype(ETHERTYPE_IP);
		b1 = gen_cmp_ge(OR_NET, 16, BPF_B, (bpf_int32)224);
		gen_and(b0, b1);
		return b1;

	case Q_IPV6:
		b0 = gen_linktype(ETHERTYPE_IPV6);
		b1 = gen_cmp(OR_NET, 24, BPF_B, (bpf_int32)255);
		gen_and(b0, b1);
		return b1;
	}
	bpf_error("link-layer multicast filters supported only on ethernet/FDDI/token ring/ARCNET/802.11/ATM LANE/Fibre Channel");
	/* NOTREACHED */
	return NULL;
}

/*
 * Filter on inbound (dir == 0) or outbound (dir == 1) traffic.
 * Outbound traffic is sent by this machine, while inbound traffic is
 * sent by a remote machine (and may include packets destined for a
 * unicast or multicast link-layer address we are not subscribing to).
 * These are the same definitions implemented by pcap_setdirection().
 * Capturing only unicast traffic destined for this host is probably
 * better accomplished using a higher-layer filter.
 */
struct block *
gen_inbound(dir)
	int dir;
{
	register struct block *b0;

	/*
	 * Only some data link types support inbound/outbound qualifiers.
	 */
	switch (linktype) {
	case DLT_SLIP:
		b0 = gen_relation(BPF_JEQ,
			  gen_load(Q_LINK, gen_loadi(0), 1),
			  gen_loadi(0),
			  dir);
		break;

	case DLT_IPNET:
		if (dir) {
			/* match outgoing packets */
			b0 = gen_cmp(OR_LINK, 2, BPF_H, IPNET_OUTBOUND);
		} else {
			/* match incoming packets */
			b0 = gen_cmp(OR_LINK, 2, BPF_H, IPNET_INBOUND);
		}
		break;

	case DLT_LINUX_SLL:
		/* match outgoing packets */
		b0 = gen_cmp(OR_LINK, 0, BPF_H, LINUX_SLL_OUTGOING);
		if (!dir) {
			/* to filter on inbound traffic, invert the match */
			gen_not(b0);
		}
		break;

#ifdef HAVE_NET_PFVAR_H
	case DLT_PFLOG:
		b0 = gen_cmp(OR_LINK, offsetof(struct pfloghdr, dir), BPF_B,
		    (bpf_int32)((dir == 0) ? PF_IN : PF_OUT));
		break;
#endif

	case DLT_PPP_PPPD:
		if (dir) {
			/* match outgoing packets */
			b0 = gen_cmp(OR_LINK, 0, BPF_B, PPP_PPPD_OUT);
		} else {
			/* match incoming packets */
			b0 = gen_cmp(OR_LINK, 0, BPF_B, PPP_PPPD_IN);
		}
		break;

        case DLT_JUNIPER_MFR:
        case DLT_JUNIPER_MLFR:
        case DLT_JUNIPER_MLPPP:
	case DLT_JUNIPER_ATM1:
	case DLT_JUNIPER_ATM2:
	case DLT_JUNIPER_PPPOE:
	case DLT_JUNIPER_PPPOE_ATM:
        case DLT_JUNIPER_GGSN:
        case DLT_JUNIPER_ES:
        case DLT_JUNIPER_MONITOR:
        case DLT_JUNIPER_SERVICES:
        case DLT_JUNIPER_ETHER:
        case DLT_JUNIPER_PPP:
        case DLT_JUNIPER_FRELAY:
        case DLT_JUNIPER_CHDLC:
        case DLT_JUNIPER_VP:
        case DLT_JUNIPER_ST:
        case DLT_JUNIPER_ISM:
        case DLT_JUNIPER_VS:
        case DLT_JUNIPER_SRX_E2E:
        case DLT_JUNIPER_FIBRECHANNEL:
	case DLT_JUNIPER_ATM_CEMIC:

		/* juniper flags (including direction) are stored
		 * the byte after the 3-byte magic number */
		if (dir) {
			/* match outgoing packets */
			b0 = gen_mcmp(OR_LINK, 3, BPF_B, 0, 0x01);
		} else {
			/* match incoming packets */
			b0 = gen_mcmp(OR_LINK, 3, BPF_B, 1, 0x01);
		}
		break;

	default:
		/*
		 * If we have packet meta-data indicating a direction,
		 * check it, otherwise give up as this link-layer type
		 * has nothing in the packet data.
		 */
#if defined(linux) && defined(PF_PACKET) && defined(SO_ATTACH_FILTER)
		/*
		 * This is Linux with PF_PACKET support.
		 * If this is a *live* capture, we can look at
		 * special meta-data in the filter expression;
		 * if it's a savefile, we can't.
		 */
		if (bpf_pcap->rfile != NULL) {
			/* We have a FILE *, so this is a savefile */
			bpf_error("inbound/outbound not supported on linktype %d when reading savefiles",
			    linktype);
			b0 = NULL;
			/* NOTREACHED */
		}
		/* match outgoing packets */
		b0 = gen_cmp(OR_LINK, SKF_AD_OFF + SKF_AD_PKTTYPE, BPF_H,
		             PACKET_OUTGOING);
		if (!dir) {
			/* to filter on inbound traffic, invert the match */
			gen_not(b0);
		}
#else /* defined(linux) && defined(PF_PACKET) && defined(SO_ATTACH_FILTER) */
		bpf_error("inbound/outbound not supported on linktype %d",
		    linktype);
		b0 = NULL;
		/* NOTREACHED */
#endif /* defined(linux) && defined(PF_PACKET) && defined(SO_ATTACH_FILTER) */
	}
	return (b0);
}

#ifdef HAVE_NET_PFVAR_H
/* PF firewall log matched interface */
struct block *
gen_pf_ifname(const char *ifname)
{
	struct block *b0;
	u_int len, off;

	if (linktype != DLT_PFLOG) {
		bpf_error("ifname supported only on PF linktype");
		/* NOTREACHED */
	}
	len = sizeof(((struct pfloghdr *)0)->ifname);
	off = offsetof(struct pfloghdr, ifname);
	if (strlen(ifname) >= len) {
		bpf_error("ifname interface names can only be %d characters",
		    len-1);
		/* NOTREACHED */
	}
	b0 = gen_bcmp(OR_LINK, off, strlen(ifname), (const u_char *)ifname);
	return (b0);
}

/* PF firewall log ruleset name */
struct block *
gen_pf_ruleset(char *ruleset)
{
	struct block *b0;

	if (linktype != DLT_PFLOG) {
		bpf_error("ruleset supported only on PF linktype");
		/* NOTREACHED */
	}

	if (strlen(ruleset) >= sizeof(((struct pfloghdr *)0)->ruleset)) {
		bpf_error("ruleset names can only be %ld characters",
		    (long)(sizeof(((struct pfloghdr *)0)->ruleset) - 1));
		/* NOTREACHED */
	}

	b0 = gen_bcmp(OR_LINK, offsetof(struct pfloghdr, ruleset),
	    strlen(ruleset), (const u_char *)ruleset);
	return (b0);
}

/* PF firewall log rule number */
struct block *
gen_pf_rnr(int rnr)
{
	struct block *b0;

	if (linktype != DLT_PFLOG) {
		bpf_error("rnr supported only on PF linktype");
		/* NOTREACHED */
	}

	b0 = gen_cmp(OR_LINK, offsetof(struct pfloghdr, rulenr), BPF_W,
		 (bpf_int32)rnr);
	return (b0);
}

/* PF firewall log sub-rule number */
struct block *
gen_pf_srnr(int srnr)
{
	struct block *b0;

	if (linktype != DLT_PFLOG) {
		bpf_error("srnr supported only on PF linktype");
		/* NOTREACHED */
	}

	b0 = gen_cmp(OR_LINK, offsetof(struct pfloghdr, subrulenr), BPF_W,
	    (bpf_int32)srnr);
	return (b0);
}

/* PF firewall log reason code */
struct block *
gen_pf_reason(int reason)
{
	struct block *b0;

	if (linktype != DLT_PFLOG) {
		bpf_error("reason supported only on PF linktype");
		/* NOTREACHED */
	}

	b0 = gen_cmp(OR_LINK, offsetof(struct pfloghdr, reason), BPF_B,
	    (bpf_int32)reason);
	return (b0);
}

/* PF firewall log action */
struct block *
gen_pf_action(int action)
{
	struct block *b0;

	if (linktype != DLT_PFLOG) {
		bpf_error("action supported only on PF linktype");
		/* NOTREACHED */
	}

	b0 = gen_cmp(OR_LINK, offsetof(struct pfloghdr, action), BPF_B,
	    (bpf_int32)action);
	return (b0);
}
#else /* !HAVE_NET_PFVAR_H */
struct block *
gen_pf_ifname(const char *ifname)
{
	bpf_error("libpcap was compiled without pf support");
	/* NOTREACHED */
	return (NULL);
}

struct block *
gen_pf_ruleset(char *ruleset)
{
	bpf_error("libpcap was compiled on a machine without pf support");
	/* NOTREACHED */
	return (NULL);
}

struct block *
gen_pf_rnr(int rnr)
{
	bpf_error("libpcap was compiled on a machine without pf support");
	/* NOTREACHED */
	return (NULL);
}

struct block *
gen_pf_srnr(int srnr)
{
	bpf_error("libpcap was compiled on a machine without pf support");
	/* NOTREACHED */
	return (NULL);
}

struct block *
gen_pf_reason(int reason)
{
	bpf_error("libpcap was compiled on a machine without pf support");
	/* NOTREACHED */
	return (NULL);
}

struct block *
gen_pf_action(int action)
{
	bpf_error("libpcap was compiled on a machine without pf support");
	/* NOTREACHED */
	return (NULL);
}
#endif /* HAVE_NET_PFVAR_H */

/* IEEE 802.11 wireless header */
struct block *
gen_p80211_type(int type, int mask)
{
	struct block *b0;

	switch (linktype) {

	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
		b0 = gen_mcmp(OR_LINK, 0, BPF_B, (bpf_int32)type,
		    (bpf_int32)mask);
		break;

	default:
		bpf_error("802.11 link-layer types supported only on 802.11");
		/* NOTREACHED */
	}

	return (b0);
}

struct block *
gen_p80211_fcdir(int fcdir)
{
	struct block *b0;

	switch (linktype) {

	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO_AVS:
	case DLT_IEEE802_11_RADIO:
		break;

	default:
		bpf_error("frame direction supported only with 802.11 headers");
		/* NOTREACHED */
	}

	b0 = gen_mcmp(OR_LINK, 1, BPF_B, (bpf_int32)fcdir,
		(bpf_u_int32)IEEE80211_FC1_DIR_MASK);

	return (b0);
}

struct block *
gen_acode(eaddr, q)
	register const u_char *eaddr;
	struct qual q;
{
	switch (linktype) {

	case DLT_ARCNET:
	case DLT_ARCNET_LINUX:
		if ((q.addr == Q_HOST || q.addr == Q_DEFAULT) &&
		    q.proto == Q_LINK)
			return (gen_ahostop(eaddr, (int)q.dir));
		else {
			bpf_error("ARCnet address used in non-arc expression");
			/* NOTREACHED */
		}
		break;

	default:
		bpf_error("aid supported only on ARCnet");
		/* NOTREACHED */
	}
	bpf_error("ARCnet address used in non-arc expression");
	/* NOTREACHED */
	return NULL;
}

static struct block *
gen_ahostop(eaddr, dir)
	register const u_char *eaddr;
	register int dir;
{
	register struct block *b0, *b1;

	switch (dir) {
	/* src comes first, different from Ethernet */
	case Q_SRC:
		return gen_bcmp(OR_LINK, 0, 1, eaddr);

	case Q_DST:
		return gen_bcmp(OR_LINK, 1, 1, eaddr);

	case Q_AND:
		b0 = gen_ahostop(eaddr, Q_SRC);
		b1 = gen_ahostop(eaddr, Q_DST);
		gen_and(b0, b1);
		return b1;

	case Q_DEFAULT:
	case Q_OR:
		b0 = gen_ahostop(eaddr, Q_SRC);
		b1 = gen_ahostop(eaddr, Q_DST);
		gen_or(b0, b1);
		return b1;

	case Q_ADDR1:
		bpf_error("'addr1' is only supported on 802.11");
		break;

	case Q_ADDR2:
		bpf_error("'addr2' is only supported on 802.11");
		break;

	case Q_ADDR3:
		bpf_error("'addr3' is only supported on 802.11");
		break;

	case Q_ADDR4:
		bpf_error("'addr4' is only supported on 802.11");
		break;

	case Q_RA:
		bpf_error("'ra' is only supported on 802.11");
		break;

	case Q_TA:
		bpf_error("'ta' is only supported on 802.11");
		break;
	}
	abort();
	/* NOTREACHED */
}

/*
 * support IEEE 802.1Q VLAN trunk over ethernet
 */
struct block *
gen_vlan(vlan_num)
	int vlan_num;
{
	struct	block	*b0, *b1;

	/* can't check for VLAN-encapsulated packets inside MPLS */
	if (label_stack_depth > 0)
		bpf_error("no VLAN match after MPLS");

	/*
	 * Check for a VLAN packet, and then change the offsets to point
	 * to the type and data fields within the VLAN packet.  Just
	 * increment the offsets, so that we can support a hierarchy, e.g.
	 * "vlan 300 && vlan 200" to capture VLAN 200 encapsulated within
	 * VLAN 100.
	 *
	 * XXX - this is a bit of a kludge.  If we were to split the
	 * compiler into a parser that parses an expression and
	 * generates an expression tree, and a code generator that
	 * takes an expression tree (which could come from our
	 * parser or from some other parser) and generates BPF code,
	 * we could perhaps make the offsets parameters of routines
	 * and, in the handler for an "AND" node, pass to subnodes
	 * other than the VLAN node the adjusted offsets.
	 *
	 * This would mean that "vlan" would, instead of changing the
	 * behavior of *all* tests after it, change only the behavior
	 * of tests ANDed with it.  That would change the documented
	 * semantics of "vlan", which might break some expressions.
	 * However, it would mean that "(vlan and ip) or ip" would check
	 * both for VLAN-encapsulated IP and IP-over-Ethernet, rather than
	 * checking only for VLAN-encapsulated IP, so that could still
	 * be considered worth doing; it wouldn't break expressions
	 * that are of the form "vlan and ..." or "vlan N and ...",
	 * which I suspect are the most common expressions involving
	 * "vlan".  "vlan or ..." doesn't necessarily do what the user
	 * would really want, now, as all the "or ..." tests would
	 * be done assuming a VLAN, even though the "or" could be viewed
	 * as meaning "or, if this isn't a VLAN packet...".
	 */
	orig_nl = off_nl;

	switch (linktype) {

	case DLT_EN10MB:
	case DLT_NETANALYZER:
	case DLT_NETANALYZER_TRANSPARENT:
		/* check for VLAN, including QinQ */
		b0 = gen_cmp(OR_LINK, off_linktype, BPF_H,
		    (bpf_int32)ETHERTYPE_8021Q);
		b1 = gen_cmp(OR_LINK, off_linktype, BPF_H,
		    (bpf_int32)ETHERTYPE_8021QINQ);
		gen_or(b0,b1);
		b0 = b1;

		/* If a specific VLAN is requested, check VLAN id */
		if (vlan_num >= 0) {
			b1 = gen_mcmp(OR_MACPL, 0, BPF_H,
			    (bpf_int32)vlan_num, 0x0fff);
			gen_and(b0, b1);
			b0 = b1;
		}

		off_macpl += 4;
		off_linktype += 4;
#if 0
		off_nl_nosnap += 4;
		off_nl += 4;
#endif
		break;

	default:
		bpf_error("no VLAN support for data link type %d",
		      linktype);
		/*NOTREACHED*/
	}

	return (b0);
}

/*
 * support for MPLS
 */
struct block *
gen_mpls(label_num)
	int label_num;
{
	struct	block	*b0,*b1;

	/*
	 * Change the offsets to point to the type and data fields within
	 * the MPLS packet.  Just increment the offsets, so that we
	 * can support a hierarchy, e.g. "mpls 100000 && mpls 1024" to
	 * capture packets with an outer label of 100000 and an inner
	 * label of 1024.
	 *
	 * XXX - this is a bit of a kludge.  See comments in gen_vlan().
	 */
        orig_nl = off_nl;

        if (label_stack_depth > 0) {
            /* just match the bottom-of-stack bit clear */
            b0 = gen_mcmp(OR_MACPL, orig_nl-2, BPF_B, 0, 0x01);
        } else {
            /*
             * Indicate that we're checking MPLS-encapsulated headers,
             * to make sure higher level code generators don't try to
             * match against IP-related protocols such as Q_ARP, Q_RARP
             * etc.
             */
            switch (linktype) {
                
            case DLT_C_HDLC: /* fall through */
            case DLT_EN10MB:
            case DLT_NETANALYZER:
            case DLT_NETANALYZER_TRANSPARENT:
                    b0 = gen_linktype(ETHERTYPE_MPLS);
                    break;
                
            case DLT_PPP:
                    b0 = gen_linktype(PPP_MPLS_UCAST);
                    break;
                
                    /* FIXME add other DLT_s ...
                     * for Frame-Relay/and ATM this may get messy due to SNAP headers
                     * leave it for now */
                
            default:
                    bpf_error("no MPLS support for data link type %d",
                          linktype);
                    b0 = NULL;
                    /*NOTREACHED*/
                    break;
            }
        }

	/* If a specific MPLS label is requested, check it */
	if (label_num >= 0) {
		label_num = label_num << 12; /* label is shifted 12 bits on the wire */
		b1 = gen_mcmp(OR_MACPL, orig_nl, BPF_W, (bpf_int32)label_num,
		    0xfffff000); /* only compare the first 20 bits */
		gen_and(b0, b1);
		b0 = b1;
	}

        off_nl_nosnap += 4;
        off_nl += 4;
        label_stack_depth++;
	return (b0);
}

/*
 * Support PPPOE discovery and session.
 */
struct block *
gen_pppoed()
{
	/* check for PPPoE discovery */
	return gen_linktype((bpf_int32)ETHERTYPE_PPPOED);
}

struct block *
gen_pppoes(sess_num)
	int sess_num;
{
	struct block *b0, *b1;

	/*
	 * Test against the PPPoE session link-layer type.
	 */
	b0 = gen_linktype((bpf_int32)ETHERTYPE_PPPOES);

	/*
	 * Change the offsets to point to the type and data fields within
	 * the PPP packet, and note that this is PPPoE rather than
	 * raw PPP.
	 *
	 * XXX - this is a bit of a kludge.  If we were to split the
	 * compiler into a parser that parses an expression and
	 * generates an expression tree, and a code generator that
	 * takes an expression tree (which could come from our
	 * parser or from some other parser) and generates BPF code,
	 * we could perhaps make the offsets parameters of routines
	 * and, in the handler for an "AND" node, pass to subnodes
	 * other than the PPPoE node the adjusted offsets.
	 *
	 * This would mean that "pppoes" would, instead of changing the
	 * behavior of *all* tests after it, change only the behavior
	 * of tests ANDed with it.  That would change the documented
	 * semantics of "pppoes", which might break some expressions.
	 * However, it would mean that "(pppoes and ip) or ip" would check
	 * both for VLAN-encapsulated IP and IP-over-Ethernet, rather than
	 * checking only for VLAN-encapsulated IP, so that could still
	 * be considered worth doing; it wouldn't break expressions
	 * that are of the form "pppoes and ..." which I suspect are the
	 * most common expressions involving "pppoes".  "pppoes or ..."
	 * doesn't necessarily do what the user would really want, now,
	 * as all the "or ..." tests would be done assuming PPPoE, even
	 * though the "or" could be viewed as meaning "or, if this isn't
	 * a PPPoE packet...".
	 */
	orig_linktype = off_linktype;	/* save original values */
	orig_nl = off_nl;
	is_pppoes = 1;

	/* If a specific session is requested, check PPPoE session id */
	if (sess_num >= 0) {
		b1 = gen_mcmp(OR_MACPL, orig_nl, BPF_W,
		    (bpf_int32)sess_num, 0x0000ffff);
		gen_and(b0, b1);
		b0 = b1;
	}

	/*
	 * The "network-layer" protocol is PPPoE, which has a 6-byte
	 * PPPoE header, followed by a PPP packet.
	 *
	 * There is no HDLC encapsulation for the PPP packet (it's
	 * encapsulated in PPPoES instead), so the link-layer type
	 * starts at the first byte of the PPP packet.  For PPPoE,
	 * that offset is relative to the beginning of the total
	 * link-layer payload, including any 802.2 LLC header, so
	 * it's 6 bytes past off_nl.
	 */
	off_linktype = off_nl + 6;

	/*
	 * The network-layer offsets are relative to the beginning
	 * of the MAC-layer payload; that's past the 6-byte
	 * PPPoE header and the 2-byte PPP header.
	 */
	off_nl = 6+2;
	off_nl_nosnap = 6+2;

	return b0;
}

struct block *
gen_atmfield_code(atmfield, jvalue, jtype, reverse)
	int atmfield;
	bpf_int32 jvalue;
	bpf_u_int32 jtype;
	int reverse;
{
	struct block *b0;

	switch (atmfield) {

	case A_VPI:
		if (!is_atm)
			bpf_error("'vpi' supported only on raw ATM");
		if (off_vpi == (u_int)-1)
			abort();
		b0 = gen_ncmp(OR_LINK, off_vpi, BPF_B, 0xffffffff, jtype,
		    reverse, jvalue);
		break;

	case A_VCI:
		if (!is_atm)
			bpf_error("'vci' supported only on raw ATM");
		if (off_vci == (u_int)-1)
			abort();
		b0 = gen_ncmp(OR_LINK, off_vci, BPF_H, 0xffffffff, jtype,
		    reverse, jvalue);
		break;

	case A_PROTOTYPE:
		if (off_proto == (u_int)-1)
			abort();	/* XXX - this isn't on FreeBSD */
		b0 = gen_ncmp(OR_LINK, off_proto, BPF_B, 0x0f, jtype,
		    reverse, jvalue);
		break;

	case A_MSGTYPE:
		if (off_payload == (u_int)-1)
			abort();
		b0 = gen_ncmp(OR_LINK, off_payload + MSG_TYPE_POS, BPF_B,
		    0xffffffff, jtype, reverse, jvalue);
		break;

	case A_CALLREFTYPE:
		if (!is_atm)
			bpf_error("'callref' supported only on raw ATM");
		if (off_proto == (u_int)-1)
			abort();
		b0 = gen_ncmp(OR_LINK, off_proto, BPF_B, 0xffffffff,
		    jtype, reverse, jvalue);
		break;

	default:
		abort();
	}
	return b0;
}

struct block *
gen_atmtype_abbrev(type)
	int type;
{
	struct block *b0, *b1;

	switch (type) {

	case A_METAC:
		/* Get all packets in Meta signalling Circuit */
		if (!is_atm)
			bpf_error("'metac' supported only on raw ATM");
		b0 = gen_atmfield_code(A_VPI, 0, BPF_JEQ, 0);
		b1 = gen_atmfield_code(A_VCI, 1, BPF_JEQ, 0);
		gen_and(b0, b1);
		break;

	case A_BCC:
		/* Get all packets in Broadcast Circuit*/
		if (!is_atm)
			bpf_error("'bcc' supported only on raw ATM");
		b0 = gen_atmfield_code(A_VPI, 0, BPF_JEQ, 0);
		b1 = gen_atmfield_code(A_VCI, 2, BPF_JEQ, 0);
		gen_and(b0, b1);
		break;

	case A_OAMF4SC:
		/* Get all cells in Segment OAM F4 circuit*/
		if (!is_atm)
			bpf_error("'oam4sc' supported only on raw ATM");
		b0 = gen_atmfield_code(A_VPI, 0, BPF_JEQ, 0);
		b1 = gen_atmfield_code(A_VCI, 3, BPF_JEQ, 0);
		gen_and(b0, b1);
		break;

	case A_OAMF4EC:
		/* Get all cells in End-to-End OAM F4 Circuit*/
		if (!is_atm)
			bpf_error("'oam4ec' supported only on raw ATM");
		b0 = gen_atmfield_code(A_VPI, 0, BPF_JEQ, 0);
		b1 = gen_atmfield_code(A_VCI, 4, BPF_JEQ, 0);
		gen_and(b0, b1);
		break;

	case A_SC:
		/*  Get all packets in connection Signalling Circuit */
		if (!is_atm)
			bpf_error("'sc' supported only on raw ATM");
		b0 = gen_atmfield_code(A_VPI, 0, BPF_JEQ, 0);
		b1 = gen_atmfield_code(A_VCI, 5, BPF_JEQ, 0);
		gen_and(b0, b1);
		break;

	case A_ILMIC:
		/* Get all packets in ILMI Circuit */
		if (!is_atm)
			bpf_error("'ilmic' supported only on raw ATM");
		b0 = gen_atmfield_code(A_VPI, 0, BPF_JEQ, 0);
		b1 = gen_atmfield_code(A_VCI, 16, BPF_JEQ, 0);
		gen_and(b0, b1);
		break;

	case A_LANE:
		/* Get all LANE packets */
		if (!is_atm)
			bpf_error("'lane' supported only on raw ATM");
		b1 = gen_atmfield_code(A_PROTOTYPE, PT_LANE, BPF_JEQ, 0);

		/*
		 * Arrange that all subsequent tests assume LANE
		 * rather than LLC-encapsulated packets, and set
		 * the offsets appropriately for LANE-encapsulated
		 * Ethernet.
		 *
		 * "off_mac" is the offset of the Ethernet header,
		 * which is 2 bytes past the ATM pseudo-header
		 * (skipping the pseudo-header and 2-byte LE Client
		 * field).  The other offsets are Ethernet offsets
		 * relative to "off_mac".
		 */
		is_lane = 1;
		off_mac = off_payload + 2;	/* MAC header */
		off_linktype = off_mac + 12;
		off_macpl = off_mac + 14;	/* Ethernet */
		off_nl = 0;			/* Ethernet II */
		off_nl_nosnap = 3;		/* 802.3+802.2 */
		break;

	case A_LLC:
		/* Get all LLC-encapsulated packets */
		if (!is_atm)
			bpf_error("'llc' supported only on raw ATM");
		b1 = gen_atmfield_code(A_PROTOTYPE, PT_LLC, BPF_JEQ, 0);
		is_lane = 0;
		break;

	default:
		abort();
	}
	return b1;
}

/* 
 * Filtering for MTP2 messages based on li value
 * FISU, length is null
 * LSSU, length is 1 or 2
 * MSU, length is 3 or more
 * For MTP2_HSL, sequences are on 2 bytes, and length on 9 bits
 */
struct block *
gen_mtp2type_abbrev(type)
	int type;
{
	struct block *b0, *b1;

	switch (type) {

	case M_FISU:
		if ( (linktype != DLT_MTP2) &&
		     (linktype != DLT_ERF) &&
		     (linktype != DLT_MTP2_WITH_PHDR) )
			bpf_error("'fisu' supported only on MTP2");
		/* gen_ncmp(offrel, offset, size, mask, jtype, reverse, value) */
		b0 = gen_ncmp(OR_PACKET, off_li, BPF_B, 0x3f, BPF_JEQ, 0, 0);
		break;

	case M_LSSU:
		if ( (linktype != DLT_MTP2) &&
		     (linktype != DLT_ERF) &&
		     (linktype != DLT_MTP2_WITH_PHDR) )
			bpf_error("'lssu' supported only on MTP2");
		b0 = gen_ncmp(OR_PACKET, off_li, BPF_B, 0x3f, BPF_JGT, 1, 2);
		b1 = gen_ncmp(OR_PACKET, off_li, BPF_B, 0x3f, BPF_JGT, 0, 0);
		gen_and(b1, b0);
		break;

	case M_MSU:
		if ( (linktype != DLT_MTP2) &&
		     (linktype != DLT_ERF) &&
		     (linktype != DLT_MTP2_WITH_PHDR) )
			bpf_error("'msu' supported only on MTP2");
		b0 = gen_ncmp(OR_PACKET, off_li, BPF_B, 0x3f, BPF_JGT, 0, 2);
		break;

	case MH_FISU:
		if ( (linktype != DLT_MTP2) &&
		     (linktype != DLT_ERF) &&
		     (linktype != DLT_MTP2_WITH_PHDR) )
			bpf_error("'hfisu' supported only on MTP2_HSL");
		/* gen_ncmp(offrel, offset, size, mask, jtype, reverse, value) */
		b0 = gen_ncmp(OR_PACKET, off_li_hsl, BPF_H, 0xff80, BPF_JEQ, 0, 0);
		break;

	case MH_LSSU:
		if ( (linktype != DLT_MTP2) &&
		     (linktype != DLT_ERF) &&
		     (linktype != DLT_MTP2_WITH_PHDR) )
			bpf_error("'hlssu' supported only on MTP2_HSL");
		b0 = gen_ncmp(OR_PACKET, off_li_hsl, BPF_H, 0xff80, BPF_JGT, 1, 0x0100);
		b1 = gen_ncmp(OR_PACKET, off_li_hsl, BPF_H, 0xff80, BPF_JGT, 0, 0);
		gen_and(b1, b0);
		break;

	case MH_MSU:
		if ( (linktype != DLT_MTP2) &&
		     (linktype != DLT_ERF) &&
		     (linktype != DLT_MTP2_WITH_PHDR) )
			bpf_error("'hmsu' supported only on MTP2_HSL");
		b0 = gen_ncmp(OR_PACKET, off_li_hsl, BPF_H, 0xff80, BPF_JGT, 0, 0x0100);
		break;

	default:
		abort();
	}
	return b0;
}

struct block *
gen_mtp3field_code(mtp3field, jvalue, jtype, reverse)
	int mtp3field;
	bpf_u_int32 jvalue;
	bpf_u_int32 jtype;
	int reverse;
{
	struct block *b0;
	bpf_u_int32 val1 , val2 , val3;
	u_int newoff_sio=off_sio;
	u_int newoff_opc=off_opc;
	u_int newoff_dpc=off_dpc;
	u_int newoff_sls=off_sls;

	switch (mtp3field) {

	case MH_SIO:
		newoff_sio += 3; /* offset for MTP2_HSL */
		/* FALLTHROUGH */

	case M_SIO:
		if (off_sio == (u_int)-1)
			bpf_error("'sio' supported only on SS7");
		/* sio coded on 1 byte so max value 255 */
		if(jvalue > 255)
		        bpf_error("sio value %u too big; max value = 255",
		            jvalue);
		b0 = gen_ncmp(OR_PACKET, newoff_sio, BPF_B, 0xffffffff,
		    (u_int)jtype, reverse, (u_int)jvalue);
		break;

	case MH_OPC:
		newoff_opc+=3;
        case M_OPC:
	        if (off_opc == (u_int)-1)
			bpf_error("'opc' supported only on SS7");
		/* opc coded on 14 bits so max value 16383 */
		if (jvalue > 16383)
		        bpf_error("opc value %u too big; max value = 16383",
		            jvalue);
		/* the following instructions are made to convert jvalue
		 * to the form used to write opc in an ss7 message*/
		val1 = jvalue & 0x00003c00;
		val1 = val1 >>10;
		val2 = jvalue & 0x000003fc;
		val2 = val2 <<6;
		val3 = jvalue & 0x00000003;
		val3 = val3 <<22;
		jvalue = val1 + val2 + val3;
		b0 = gen_ncmp(OR_PACKET, newoff_opc, BPF_W, 0x00c0ff0f,
		    (u_int)jtype, reverse, (u_int)jvalue);
		break;

	case MH_DPC:
		newoff_dpc += 3;
		/* FALLTHROUGH */

	case M_DPC:
	        if (off_dpc == (u_int)-1)
			bpf_error("'dpc' supported only on SS7");
		/* dpc coded on 14 bits so max value 16383 */
		if (jvalue > 16383)
		        bpf_error("dpc value %u too big; max value = 16383",
		            jvalue);
		/* the following instructions are made to convert jvalue
		 * to the forme used to write dpc in an ss7 message*/
		val1 = jvalue & 0x000000ff;
		val1 = val1 << 24;
		val2 = jvalue & 0x00003f00;
		val2 = val2 << 8;
		jvalue = val1 + val2;
		b0 = gen_ncmp(OR_PACKET, newoff_dpc, BPF_W, 0xff3f0000,
		    (u_int)jtype, reverse, (u_int)jvalue);
		break;

	case MH_SLS:
	  newoff_sls+=3;
	case M_SLS:
	        if (off_sls == (u_int)-1)
			bpf_error("'sls' supported only on SS7");
		/* sls coded on 4 bits so max value 15 */
		if (jvalue > 15)
		         bpf_error("sls value %u too big; max value = 15",
		             jvalue);
		/* the following instruction is made to convert jvalue
		 * to the forme used to write sls in an ss7 message*/
		jvalue = jvalue << 4;
		b0 = gen_ncmp(OR_PACKET, newoff_sls, BPF_B, 0xf0,
		    (u_int)jtype,reverse, (u_int)jvalue);
		break;

	default:
		abort();
	}
	return b0;
}

static struct block *
gen_msg_abbrev(type)
	int type;
{
	struct block *b1;

	/*
	 * Q.2931 signalling protocol messages for handling virtual circuits
	 * establishment and teardown
	 */
	switch (type) {

	case A_SETUP:
		b1 = gen_atmfield_code(A_MSGTYPE, SETUP, BPF_JEQ, 0);
		break;

	case A_CALLPROCEED:
		b1 = gen_atmfield_code(A_MSGTYPE, CALL_PROCEED, BPF_JEQ, 0);
		break;

	case A_CONNECT:
		b1 = gen_atmfield_code(A_MSGTYPE, CONNECT, BPF_JEQ, 0);
		break;

	case A_CONNECTACK:
		b1 = gen_atmfield_code(A_MSGTYPE, CONNECT_ACK, BPF_JEQ, 0);
		break;

	case A_RELEASE:
		b1 = gen_atmfield_code(A_MSGTYPE, RELEASE, BPF_JEQ, 0);
		break;

	case A_RELEASE_DONE:
		b1 = gen_atmfield_code(A_MSGTYPE, RELEASE_DONE, BPF_JEQ, 0);
		break;

	default:
		abort();
	}
	return b1;
}

struct block *
gen_atmmulti_abbrev(type)
	int type;
{
	struct block *b0, *b1;

	switch (type) {

	case A_OAM:
		if (!is_atm)
			bpf_error("'oam' supported only on raw ATM");
		b1 = gen_atmmulti_abbrev(A_OAMF4);
		break;

	case A_OAMF4:
		if (!is_atm)
			bpf_error("'oamf4' supported only on raw ATM");
		/* OAM F4 type */
		b0 = gen_atmfield_code(A_VCI, 3, BPF_JEQ, 0);
		b1 = gen_atmfield_code(A_VCI, 4, BPF_JEQ, 0);
		gen_or(b0, b1);
		b0 = gen_atmfield_code(A_VPI, 0, BPF_JEQ, 0);
		gen_and(b0, b1);
		break;

	case A_CONNECTMSG:
		/*
		 * Get Q.2931 signalling messages for switched
		 * virtual connection
		 */
		if (!is_atm)
			bpf_error("'connectmsg' supported only on raw ATM");
		b0 = gen_msg_abbrev(A_SETUP);
		b1 = gen_msg_abbrev(A_CALLPROCEED);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(A_CONNECT);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(A_CONNECTACK);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(A_RELEASE);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(A_RELEASE_DONE);
		gen_or(b0, b1);
		b0 = gen_atmtype_abbrev(A_SC);
		gen_and(b0, b1);
		break;

	case A_METACONNECT:
		if (!is_atm)
			bpf_error("'metaconnect' supported only on raw ATM");
		b0 = gen_msg_abbrev(A_SETUP);
		b1 = gen_msg_abbrev(A_CALLPROCEED);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(A_CONNECT);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(A_RELEASE);
		gen_or(b0, b1);
		b0 = gen_msg_abbrev(A_RELEASE_DONE);
		gen_or(b0, b1);
		b0 = gen_atmtype_abbrev(A_METAC);
		gen_and(b0, b1);
		break;

	default:
		abort();
	}
	return b1;
}
