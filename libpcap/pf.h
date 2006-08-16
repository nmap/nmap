/*
 * Copyright (c) 2001 Daniel Hartmeier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer. 
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * @(#) $Header: /tcpdump/master/libpcap/pf.h,v 1.3 2004/04/02 06:33:30 guy Exp $ (LBL)
 */

/*	from $OpenBSD: pfvar.h,v 1.170 2003/08/22 21:50:34 david Exp $ */

enum	{ PF_INOUT=0, PF_IN=1, PF_OUT=2 };
enum	{ PF_PASS=0, PF_DROP=1, PF_SCRUB=2, PF_NAT=3, PF_NONAT=4,
	  PF_BINAT=5, PF_NOBINAT=6, PF_RDR=7, PF_NORDR=8, PF_SYNPROXY_DROP=9 };

/* Reasons code for passing/dropping a packet */
#define PFRES_MATCH	0		/* Explicit match of a rule */
#define PFRES_BADOFF	1		/* Bad offset for pull_hdr */
#define PFRES_FRAG	2		/* Dropping following fragment */
#define PFRES_SHORT	3		/* Dropping short packet */
#define PFRES_NORM	4		/* Dropping by normalizer */
#define PFRES_MEMORY	5		/* Dropped due to lacking mem */
#define PFRES_MAX	6		/* total+1 */

#define PFRES_NAMES { \
	"match", \
	"bad-offset", \
	"fragment", \
	"short", \
	"normalize", \
	"memory", \
	NULL \
}

#define PF_RULESET_NAME_SIZE	16

/*	from $OpenBSD: if_pflog.h,v 1.9 2003/07/15 20:27:27 dhartmei Exp $ */

#ifndef IFNAMSIZ
#define	IFNAMSIZ	16
#endif

struct pfloghdr {
	u_int8_t	length;
	u_int8_t	af;
	u_int8_t	action;
	u_int8_t	reason;
	char		ifname[IFNAMSIZ];
	char		ruleset[PF_RULESET_NAME_SIZE];
	u_int32_t	rulenr;
	u_int32_t	subrulenr;
	u_int8_t	dir;
	u_int8_t	pad[3];
};
#define PFLOG_HDRLEN		sizeof(struct pfloghdr)
