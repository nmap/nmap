/*
 * Copyright (c) 1982, 1986, 1993, 1994, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)tcp_var.h	8.4 (Berkeley) 5/24/95
 */

/*
 * Kernel variables for tcp.
 */

/*
 * Tcp control block, one per tcp; fields:
 */
struct tcpcb {
	struct	tcpiphdr *seg_next;	/* sequencing queue */
	struct	tcpiphdr *seg_prev;
	short	t_state;		/* state of this connection */
	short	t_timer[TCPT_NTIMERS];	/* tcp timers */
	short	t_rxtshift;		/* log(2) of rexmt exp. backoff */
	short	t_rxtcur;		/* current retransmit value */
	short	t_dupacks;		/* consecutive dup acks recd */
	u_short	t_maxseg;		/* maximum segment size */
	char	t_force;		/* 1 if forcing out a byte */
	u_short	t_flags;
#define	TF_ACKNOW	0x0001		/* ack peer immediately */
#define	TF_DELACK	0x0002		/* ack, but try to delay it */
#define	TF_NODELAY	0x0004		/* don't delay packets to coalesce */
#define	TF_NOOPT	0x0008		/* don't use tcp options */
#define	TF_SENTFIN	0x0010		/* have sent FIN */
#define	TF_REQ_SCALE	0x0020		/* have/will request window scaling */
#define	TF_RCVD_SCALE	0x0040		/* other side has requested scaling */
#define	TF_REQ_TSTMP	0x0080		/* have/will request timestamps */
#define	TF_RCVD_TSTMP	0x0100		/* a timestamp was received in SYN */
#define	TF_SACK_PERMIT	0x0200		/* other side said I could SACK */

	struct	tcpiphdr *t_template;	/* skeletal packet for transmit */
	struct	inpcb *t_inpcb;		/* back pointer to internet pcb */
/*
 * The following fields are used as in the protocol specification.
 * See RFC783, Dec. 1981, page 21.
 */
/* send sequence variables */
	tcp_seq	snd_una;		/* send unacknowledged */
	tcp_seq	snd_nxt;		/* send next */
	tcp_seq	snd_up;			/* send urgent pointer */
	tcp_seq	snd_wl1;		/* window update seg seq number */
	tcp_seq	snd_wl2;		/* window update seg ack number */
	tcp_seq	iss;			/* initial send sequence number */
	n_long	snd_wnd;		/* send window */
/* receive sequence variables */
	n_long	rcv_wnd;		/* receive window */
	tcp_seq	rcv_nxt;		/* receive next */
	tcp_seq	rcv_up;			/* receive urgent pointer */
	tcp_seq	irs;			/* initial receive sequence number */
/*
 * Additional variables for this implementation.
 */
/* receive variables */
	tcp_seq	rcv_adv;		/* advertised window */
/* retransmit variables */
	tcp_seq	snd_max;		/* highest sequence number sent;
					 * used to recognize retransmits
					 */
/* congestion control (for slow start, source quench, retransmit after loss) */
	n_long	snd_cwnd;		/* congestion-controlled window */
	n_long	snd_ssthresh;		/* snd_cwnd size threshhold for
					 * for slow start exponential to
					 * linear switch
					 */
/*
 * transmit timing stuff.  See below for scale of srtt and rttvar.
 * "Variance" is actually smoothed difference.
 */
	u_short	t_idle;			/* inactivity time */
	short	t_rtt;			/* round trip time */
	tcp_seq	t_rtseq;		/* sequence number being timed */
	short	t_srtt;			/* smoothed round-trip time */
	short	t_rttvar;		/* variance in round-trip time */
	u_short	t_rttmin;		/* minimum rtt allowed */
	n_long	max_sndwnd;		/* largest window peer has offered */

/* out-of-band data */
	char	t_oobflags;		/* have some */
	char	t_iobc;			/* input character */
#define	TCPOOB_HAVEDATA	0x01
#define	TCPOOB_HADDATA	0x02
	short	t_softerror;		/* possible error not yet reported */

/* RFC 1323 variables */
	u_char	snd_scale;		/* window scaling for send window */
	u_char	rcv_scale;		/* window scaling for recv window */
	u_char	request_r_scale;	/* pending window scaling */
	u_char	requested_s_scale;
	n_long	ts_recent;		/* timestamp echo data */
	n_long	ts_recent_age;		/* when last updated */
	tcp_seq	last_ack_sent;

/* TUBA stuff */
	caddr_t	t_tuba_pcb;		/* next level down pcb for TCP over z */
};

#define	intotcpcb(ip)	((struct tcpcb *)(ip)->inp_ppcb)
#define	sototcpcb(so)	(intotcpcb(sotoinpcb(so)))

/*
 * The smoothed round-trip time and estimated variance
 * are stored as fixed point numbers scaled by the values below.
 * For convenience, these scales are also used in smoothing the average
 * (smoothed = (1/scale)sample + ((scale-1)/scale)smoothed).
 * With these scales, srtt has 3 bits to the right of the binary point,
 * and thus an "ALPHA" of 0.875.  rttvar has 2 bits to the right of the
 * binary point, and is smoothed with an ALPHA of 0.75.
 */
#define	TCP_RTT_SCALE		8	/* multiplier for srtt; 3 bits frac. */
#define	TCP_RTT_SHIFT		3	/* shift for srtt; 3 bits frac. */
#define	TCP_RTTVAR_SCALE	4	/* multiplier for rttvar; 2 bits */
#define	TCP_RTTVAR_SHIFT	2	/* multiplier for rttvar; 2 bits */

/*
 * The initial retransmission should happen at rtt + 4 * rttvar.
 * Because of the way we do the smoothing, srtt and rttvar
 * will each average +1/2 tick of bias.  When we compute
 * the retransmit timer, we want 1/2 tick of rounding and
 * 1 extra tick because of +-1/2 tick uncertainty in the
 * firing of the timer.  The bias will give us exactly the
 * 1.5 tick we need.  But, because the bias is
 * statistical, we have to test that we don't drop below
 * the minimum feasible timer (which is 2 ticks).
 * This macro assumes that the value of TCP_RTTVAR_SCALE
 * is the same as the multiplier for rttvar.
 */
#define	TCP_REXMTVAL(tp) \
	(((tp)->t_srtt >> TCP_RTT_SHIFT) + (tp)->t_rttvar)

/* XXX
 * We want to avoid doing m_pullup on incoming packets but that
 * means avoiding dtom on the tcp reassembly code.  That in turn means
 * keeping an mbuf pointer in the reassembly queue (since we might
 * have a cluster).  As a quick hack, the source & destination
 * port numbers (which are no longer needed once we've located the
 * tcpcb) are overlayed with an mbuf pointer.
 */
#define REASS_MBUF(ti) (*(struct mbuf **)&((ti)->ti_t))

/*
 * TCP statistics.
 * Many of these should be kept per connection,
 * but that's inconvenient at the moment.
 */
struct	tcpstat {
	n_long	tcps_connattempt;	/* connections initiated */
	n_long	tcps_accepts;		/* connections accepted */
	n_long	tcps_connects;		/* connections established */
	n_long	tcps_drops;		/* connections dropped */
	n_long	tcps_conndrops;		/* embryonic connections dropped */
	n_long	tcps_closed;		/* conn. closed (includes drops) */
	n_long	tcps_segstimed;		/* segs where we tried to get rtt */
	n_long	tcps_rttupdated;	/* times we succeeded */
	n_long	tcps_delack;		/* delayed acks sent */
	n_long	tcps_timeoutdrop;	/* conn. dropped in rxmt timeout */
	n_long	tcps_rexmttimeo;	/* retransmit timeouts */
	n_long	tcps_persisttimeo;	/* persist timeouts */
	n_long	tcps_keeptimeo;		/* keepalive timeouts */
	n_long	tcps_keepprobe;		/* keepalive probes sent */
	n_long	tcps_keepdrops;		/* connections dropped in keepalive */

	n_long	tcps_sndtotal;		/* total packets sent */
	n_long	tcps_sndpack;		/* data packets sent */
	n_long	tcps_sndbyte;		/* data bytes sent */
	n_long	tcps_sndrexmitpack;	/* data packets retransmitted */
	n_long	tcps_sndrexmitbyte;	/* data bytes retransmitted */
	n_long	tcps_sndacks;		/* ack-only packets sent */
	n_long	tcps_sndprobe;		/* window probes sent */
	n_long	tcps_sndurg;		/* packets sent with URG only */
	n_long	tcps_sndwinup;		/* window update-only packets sent */
	n_long	tcps_sndctrl;		/* control (SYN|FIN|RST) packets sent */

	n_long	tcps_rcvtotal;		/* total packets received */
	n_long	tcps_rcvpack;		/* packets received in sequence */
	n_long	tcps_rcvbyte;		/* bytes received in sequence */
	n_long	tcps_rcvbadsum;		/* packets received with ccksum errs */
	n_long	tcps_rcvbadoff;		/* packets received with bad offset */
	n_long	tcps_rcvshort;		/* packets received too short */
	n_long	tcps_rcvduppack;	/* duplicate-only packets received */
	n_long	tcps_rcvdupbyte;	/* duplicate-only bytes received */
	n_long	tcps_rcvpartduppack;	/* packets with some duplicate data */
	n_long	tcps_rcvpartdupbyte;	/* dup. bytes in part-dup. packets */
	n_long	tcps_rcvoopack;		/* out-of-order packets received */
	n_long	tcps_rcvoobyte;		/* out-of-order bytes received */
	n_long	tcps_rcvpackafterwin;	/* packets with data after window */
	n_long	tcps_rcvbyteafterwin;	/* bytes rcvd after window */
	n_long	tcps_rcvafterclose;	/* packets rcvd after "close" */
	n_long	tcps_rcvwinprobe;	/* rcvd window probe packets */
	n_long	tcps_rcvdupack;		/* rcvd duplicate acks */
	n_long	tcps_rcvacktoomuch;	/* rcvd acks for unsent data */
	n_long	tcps_rcvackpack;	/* rcvd ack packets */
	n_long	tcps_rcvackbyte;	/* bytes acked by rcvd acks */
	n_long	tcps_rcvwinupd;		/* rcvd window update packets */
	n_long	tcps_pawsdrop;		/* segments dropped due to PAWS */
	n_long	tcps_predack;		/* times hdr predict ok for acks */
	n_long	tcps_preddat;		/* times hdr predict ok for data pkts */
	n_long	tcps_pcbcachemiss;
	n_long	tcps_persistdrop;	/* timeout in persist state */
	n_long	tcps_badsyn;		/* bogus SYN, e.g. premature ACK */
};

#ifdef KERNEL
struct	inpcb tcb;		/* head of queue of active tcpcb's */
struct	tcpstat tcpstat;	/* tcp statistics */
n_long	tcp_now;		/* for RFC 1323 timestamps */

int	 tcp_attach __P((struct socket *));
void	 tcp_canceltimers __P((struct tcpcb *));
struct tcpcb *
	 tcp_close __P((struct tcpcb *));
void	 tcp_ctlinput __P((int, struct sockaddr *, struct ip *));
int	 tcp_ctloutput __P((int, struct socket *, int, int, struct mbuf **));
struct tcpcb *
	 tcp_disconnect __P((struct tcpcb *));
struct tcpcb *
	 tcp_drop __P((struct tcpcb *, int));
void	 tcp_dooptions __P((struct tcpcb *,
	    u_char *, int, struct tcpiphdr *, int *, n_long *, n_long *));
void	 tcp_drain __P((void));
void	 tcp_fasttimo __P((void));
void	 tcp_init __P((void));
void	 tcp_input __P((struct mbuf *, int));
int	 tcp_mss __P((struct tcpcb *, u_int));
struct tcpcb *
	 tcp_newtcpcb __P((struct inpcb *));
void	 tcp_notify __P((struct inpcb *, int));
int	 tcp_output __P((struct tcpcb *));
void	 tcp_pulloutofband __P((struct socket *,
	    struct tcpiphdr *, struct mbuf *));
void	 tcp_quench __P((struct inpcb *, int));
int	 tcp_reass __P((struct tcpcb *, struct tcpiphdr *, struct mbuf *));
void	 tcp_respond __P((struct tcpcb *,
	    struct tcpiphdr *, struct mbuf *, n_long, n_long, int));
void	 tcp_setpersist __P((struct tcpcb *));
void	 tcp_slowtimo __P((void));
struct tcpiphdr *
	 tcp_template __P((struct tcpcb *));
struct tcpcb *
	 tcp_timers __P((struct tcpcb *, int));
void	 tcp_trace __P((int, int, struct tcpcb *, struct tcpiphdr *, int));
struct tcpcb *
	 tcp_usrclosed __P((struct tcpcb *));
int	 tcp_usrreq __P((struct socket *,
	    int, struct mbuf *, struct mbuf *, struct mbuf *));
void	 tcp_xmit_timer __P((struct tcpcb *, int));
#endif
