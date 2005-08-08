
// IP packet structures...
// -----------------------
// Note: All of this is hard coded little endian!


typedef long n_long;
typedef long n_time;


struct ip
  {
    unsigned int ip_hl:4;               /* header length */
    unsigned int ip_v:4;                /* version */
    u_char ip_tos;                    /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    u_char ip_ttl;                    /* time to live */
    u_char ip_p;                      /* protocol */
    u_short ip_sum;                     /* checksum */
    struct in_addr ip_src, ip_dst;      /* source and dest address */
  };

#define    MAX_IPOPTLEN            40

/*
 *	IEEE 802.3 Ethernet magic constants.  The frame sizes omit the preamble
 *	and FCS/CRC (frame check sequence). 
 */

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_ZLEN	60		/* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */

/*
 *	These are the defined Ethernet Protocol ID's.
 */

#define ETH_P_LOOP	0x0060		/* Ethernet Loopback packet	*/
#define ETH_P_ECHO	0x0200		/* Ethernet Echo packet		*/
#define ETH_P_PUP	0x0400		/* Xerox PUP packet		*/
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_X25	0x0805		/* CCITT X.25			*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/
#define	ETH_P_BPQ	0x08FF		/* G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_DEC       0x6000          /* DEC Assigned proto           */
#define ETH_P_DNA_DL    0x6001          /* DEC DNA Dump/Load            */
#define ETH_P_DNA_RC    0x6002          /* DEC DNA Remote Console       */
#define ETH_P_DNA_RT    0x6003          /* DEC DNA Routing              */
#define ETH_P_LAT       0x6004          /* DEC LAT                      */
#define ETH_P_DIAG      0x6005          /* DEC Diagnostics              */
#define ETH_P_CUST      0x6006          /* DEC Customer use             */
#define ETH_P_SCA       0x6007          /* DEC Systems Comms Arch       */
#define ETH_P_RARP      0x8035		/* Reverse Addr Res packet	*/
#define ETH_P_ATALK	0x809B		/* Appletalk DDP		*/
#define ETH_P_AARP	0x80F3		/* Appletalk AARP		*/
#define ETH_P_IPX	0x8137		/* IPX over DIX			*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/

/*
 *	Non DIX types. Won't clash for 1500 types.
 */
 
#define ETH_P_802_3	0x0001		/* Dummy type for 802.3 frames  */
#define ETH_P_AX25	0x0002		/* Dummy protocol id for AX.25  */
#define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
#define ETH_P_802_2	0x0004		/* 802.2 frames 		*/
#define ETH_P_SNAP	0x0005		/* Internal only		*/
#define ETH_P_DDCMP     0x0006          /* DEC DDCMP: Internal only     */
#define ETH_P_WAN_PPP   0x0007          /* Dummy type for WAN PPP frames*/
#define ETH_P_PPP_MP    0x0008          /* Dummy type for PPP MP frames */
#define ETH_P_LOCALTALK 0x0009		/* Localtalk pseudo type 	*/
#define ETH_P_PPPTALK	0x0010		/* Dummy type for Atalk over PPP*/
#define ETH_P_TR_802_2	0x0011		/* 802.2 frames 		*/

struct etherproto {
	char *s;
	u_short p;
};
extern struct etherproto etherproto_db[];

// Ethernet Header
struct ether_header 
{
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	unsigned short	h_proto;		/* packet type ID field	*/
};

// ARP/RARP
///////////////////////////////////////////////////////////////////////
static u_char bcastaddr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/*
 *	This structure defines an ethernet arp header.
 */

struct arphdr
{
	unsigned short	ar_hrd;		/* format of hardware address	*/
	unsigned short	ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	unsigned short	ar_op;		/* ARP opcode (command)		*/
};

#define ARPD_UPDATE	0x01
#define ARPD_LOOKUP	0x02
#define ARPD_FLUSH	0x03

/*#define ARPHRD_ETHER	0x01

#define ARPOP_REQUEST	0x01
#define ARPOP_REPLY		0x02
#define ARPOP_REVREQUEST	0x03
#define ARPOP_REVREPLY		0x04
*/
/*
 * Ethernet Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */
struct	ether_arp {
	struct	arphdr ea_hdr;	/* fixed-size header */
	u_char	arp_sha[ETH_ALEN];	/* sender hardware address */
	u_char	arp_spa[4];	/* sender protocol address */
	u_char	arp_tha[ETH_ALEN];	/* target hardware address */
	u_char	arp_tpa[4];	/* target protocol address */
};
#define	arp_hrd	ea_hdr.ar_hrd
#define	arp_pro	ea_hdr.ar_pro
#define	arp_hln	ea_hdr.ar_hln
#define	arp_pln	ea_hdr.ar_pln
#define	arp_op	ea_hdr.ar_op

// IP Header in Little Endian
//////////////////////////////
struct iphdr {
	u_char	ip_hl:4,		/* header length */
			ip_v:4;			/* version */
	u_char	ip_tos;			/* type of service */
	short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	short	ip_off;			/* fragment offset field */
#define	IP_DF 0x4000		/* dont fragment flag */
#define	IP_MF 0x2000		/* more fragments flag */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

#define	IP_MAXPACKET	65535		/* maximum packet size */

// Definitions for options.
#define	IPOPT_COPIED(o)		((o)&0x80)
#define	IPOPT_CLASS(o)		((o)&0x60)
#define	IPOPT_NUMBER(o)		((o)&0x1f)

#define	IPOPT_CONTROL		0x00
#define	IPOPT_RESERVED1		0x20
#define	IPOPT_DEBMEAS		0x40
#define	IPOPT_RESERVED2		0x60

#define	IPOPT_EOL		0		/* end of option list */
#define	IPOPT_NOP		1		/* no operation */

#define	IPOPT_RR		7		/* record packet route */
#define	IPOPT_TS		68		/* timestamp */
#define	IPOPT_SECURITY	130		/* provide s,c,h,tcc */
#define	IPOPT_LSRR		131		/* loose source route */
#define	IPOPT_SATID		136		/* satnet id */
#define	IPOPT_SSRR		137		/* strict source route */


// Time stamp option structure.
struct	ip_timestamp {
	u_char	ipt_code;		/* IPOPT_TS */
	u_char	ipt_len;		/* size of structure (variable) */
	u_char	ipt_ptr;		/* index of current entry */
	u_char	ipt_flg:4,		/* flags, see below */
		ipt_oflw:4;			/* overflow counter */
	union ipt_timestamp {
		n_long	ipt_time[1];
		struct	ipt_ta {
			struct in_addr ipt_addr;
			n_long ipt_time;
		} ipt_ta[1];
	} ipt_timestamp;
};

/* flag bits for ipt_flg */
#define	IPOPT_TS_TSONLY		0		/* timestamps only */
#define	IPOPT_TS_TSANDADDR	1		/* timestamps and addresses */
#define	IPOPT_TS_PRESPEC	2		/* specified modules only */

/* bits for security (not byte swapped) */
#define	IPOPT_SECUR_UNCLASS	0x0000
#define	IPOPT_SECUR_CONFID	0xf135
#define	IPOPT_SECUR_EFTO	0x789a
#define	IPOPT_SECUR_MMMM	0xbc4d
#define	IPOPT_SECUR_RESTR	0xaf13
#define	IPOPT_SECUR_SECRET	0xd788
#define	IPOPT_SECUR_TOPSECRET	0x6bc5

// ICMP Header
////////////////////////////////////////////////////////////////////////
//struct icmphdr {
//	u_char	icmp_type;		/* type of message, see below */
//	u_char	icmp_code;		/* type sub code */
//	u_short	icmp_cksum;		/* ones complement cksum of struct */
//	union {
//		u_char ih_pptr;			/* ICMP_PARAMPROB */
//		struct in_addr ih_gwaddr;	/* ICMP_REDIRECT */
//		struct ih_idseq {
//			n_short	icd_id;
//			n_short	icd_seq;
//		} ih_idseq;
//		int ih_void;
//	} icmp_hun;
//#define	icmp_pptr	icmp_hun.ih_pptr
//#define	icmp_gwaddr	icmp_hun.ih_gwaddr
//#define	icmp_id		icmp_hun.ih_idseq.icd_id
//#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
//#define	icmp_void	icmp_hun.ih_void
//	union {
//		struct id_ts {
//			n_time its_otime;
//			n_time its_rtime;
//			n_time its_ttime;
//		} id_ts;
//		struct id_ip  {
//			struct iphdr idi_ip;
//			/* options and then 64 bits of data */
//		} id_ip;
//		u_long	id_mask;
//		char	id_data[1];
//	} icmp_dun;
//#define	icmp_otime	icmp_dun.id_ts.its_otime
//#define	icmp_rtime	icmp_dun.id_ts.its_rtime
//#define	icmp_ttime	icmp_dun.id_ts.its_ttime
//#define	icmp_ip		icmp_dun.id_ip.idi_ip
//#define	icmp_mask	icmp_dun.id_mask
//#define	icmp_data	icmp_dun.id_data
//};

//typedef struct icmp_hdr icmp;
/*
 * Lower bounds on packet lengths for various types.
 * For the error advice packets must first insure that the
 * packet is large enought to contain the returned ip header.
 * Only then can we do the check to see if 64 bits of packet
 * data have been returned, since we need to check the returned
 * ip header length.
 */
#define	ICMP_MINLEN	8				/* abs minimum */
#define	ICMP_TSLEN	(8 + 3 * sizeof (n_time))	/* timestamp */
#define	ICMP_MASKLEN	12				/* address mask */
#define	ICMP_ADVLENMIN	(8 + sizeof (struct ip) + 8)	/* min */
#define	ICMP_ADVLEN(p)	(8 + ((p)->icmp_ip.ip_hl << 2) + 8)
	/* N.B.: must separately check that ip_hl >= 5 */

/*
 * Definition of type and code field values.
 */
#define	ICMP_ECHOREPLY		0		/* echo reply */

/* UNREACH codes */
#define ICMP_UNREACH					3       /* dest unreachable, codes: */ 
#define ICMP_UNREACH_NET                0       /* bad net */
#define ICMP_UNREACH_HOST               1       /* bad host */
#define ICMP_UNREACH_PROTOCOL           2       /* bad protocol */
#define ICMP_UNREACH_PORT               3       /* bad port */
#define ICMP_UNREACH_NEEDFRAG           4       /* IP_DF caused drop */
#define ICMP_UNREACH_SRCFAIL            5       /* src route failed */
#define ICMP_UNREACH_NET_UNKNOWN        6       /* unknown net */
#define ICMP_UNREACH_HOST_UNKNOWN       7       /* unknown host */
#define ICMP_UNREACH_ISOLATED           8       /* src host isolated */
#define ICMP_UNREACH_NET_PROHIB         9       /* net denied */
#define ICMP_UNREACH_HOST_PROHIB        10      /* host denied */
#define ICMP_UNREACH_TOSNET             11      /* bad tos for net */
#define ICMP_UNREACH_TOSHOST            12      /* bad tos for host */
#define ICMP_UNREACH_FILTER_PROHIB      13      /* admin prohib */
#define ICMP_UNREACH_HOST_PRECEDENCE    14      /* host prec vio. */
#define ICMP_UNREACH_PRECEDENCE_CUTOFF  15      /* prec cutoff */
   

#define	ICMP_SOURCEQUENCH				4		/* packet lost, slow down */
#define ICMP_ROUTERADVERT				9       /* router advertisement */
#define ICMP_ROUTERSOLICIT				10      /* router solicitation */    
#define	ICMP_REDIRECT					5		/* shorter route, codes: */
#define	ICMP_REDIRECT_NET				0		/* for network */
#define	ICMP_REDIRECT_HOST				1		/* for host */
#define	ICMP_REDIRECT_TOSNET			2		/* for tos and net */
#define	ICMP_REDIRECT_TOSHOST			3		/* for tos and host */
#define	ICMP_ECHO						8		/* echo service */
#define	ICMP_TIMXCEED					11		/* time exceeded, code: */
#define	ICMP_TIMXCEED_INTRANS			0		/* ttl==0 in transit */
#define	ICMP_TIMXCEED_REASS				1		/* ttl==0 in reass */
#define	ICMP_PARAMPROB					12		/* ip header bad */
#define	ICMP_TSTAMP						13		/* timestamp request */
#define	ICMP_TSTAMPREPLY				14		/* timestamp reply */
#define	ICMP_IREQ						15		/* information request */
#define	ICMP_IREQREPLY					16		/* information reply */
#define	ICMP_MASKREQ					17		/* address mask request */
#define	ICMP_MASKREPLY					18		/* address mask reply */

#define	ICMP_MAXTYPE		18

#define	ICMP_INFOTYPE(type) \
	((type) == ICMP_ECHOREPLY || (type) == ICMP_ECHO || \
	(type) == ICMP_TSTAMP || (type) == ICMP_TSTAMPREPLY || \
	(type) == ICMP_IREQ || (type) == ICMP_IREQREPLY || \
	(type) == ICMP_MASKREQ || (type) == ICMP_MASKREPLY)

/*** ICMP types ********************************************************/
#define ICMP_TYPE_0     "Echo reply"
#define ICMP_TYPE_3     "Destination unreachable"
#define ICMP_TYPE_4     "Source quench"
#define ICMP_TYPE_5     "Redirect"
#define ICMP_TYPE_8     "Echo"
#define ICMP_TYPE_11    "Time exceeded"
#define ICMP_TYPE_12    "Parameter problem"
#define ICMP_TYPE_13    "Timestamp"
#define ICMP_TYPE_14    "Timestamp reply"
#define ICMP_TYPE_15    "Information request"
#define ICMP_TYPE_16    "Information reply"
#define ICMP_TYPE_17    "Address mask request"
#define ICMP_TYPE_18    "Adress mask reply"

/* pulled token stuff from tcpdump */
struct tok {
	int v;			/* value */
	char *s;		/* string */
};

// TCP
/////////////////////////////////////////////////////////////////////////
typedef	u_long	tcp_seq;

// TCP header. Per RFC 793, September, 1981. In Little Endian
struct tcphdr {
	u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	tcp_seq	th_seq;			/* sequence number */
	tcp_seq	th_ack;			/* acknowledgement number */
	u_char	th_x2:4,		/* (unused) */
		    th_off:4;		/* data offset */
	u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PSH	0x08
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
};

#define	TCPOPT_EOL	0
#define	TCPOPT_NOP	1
#define	TCPOPT_MAXSEG	2

enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING	/* now a valid state */
};

// UDP Header
//////////////////////////////////////////////////////////////////////////////
struct udphdr {
  unsigned short	source;
  unsigned short	dest;
  unsigned short	len;
  unsigned short	check;
};


// Netbios/SAMBA
//////////////////////////////////////////////////////////////////////////////
/* the basic packet size, assuming no words or bytes */
#define smb_size 39

/* offsets into message for common items */
#define smb_com 8
#define smb_rcls 9
#define smb_reh 10
#define smb_err 11
#define smb_flg 13
#define smb_flg2 14
#define smb_reb 13
#define smb_tid 28
#define smb_pid 30
#define smb_uid 32
#define smb_mid 34
#define smb_wct 36
#define smb_vwv 37
#define smb_vwv0 37
#define smb_vwv1 39
#define smb_vwv2 41
#define smb_vwv3 43
#define smb_vwv4 45
#define smb_vwv5 47
#define smb_vwv6 49
#define smb_vwv7 51
#define smb_vwv8 53
#define smb_vwv9 55
#define smb_vwv10 57
#define smb_vwv11 59
#define smb_vwv12 61
#define smb_vwv13 63
#define smb_vwv14 65
#define smb_vwv15 67
#define smb_vwv16 69
#define smb_vwv17 71

/* the complete */
#define SMBmkdir      0x00   /* create directory */
#define SMBrmdir      0x01   /* delete directory */
#define SMBopen       0x02   /* open file */
#define SMBcreate     0x03   /* create file */
#define SMBclose      0x04   /* close file */
#define SMBflush      0x05   /* flush file */
#define SMBunlink     0x06   /* delete file */
#define SMBmv         0x07   /* rename file */
#define SMBgetatr     0x08   /* get file attributes */
#define SMBsetatr     0x09   /* set file attributes */
#define SMBread       0x0A   /* read from file */
#define SMBwrite      0x0B   /* write to file */
#define SMBlock       0x0C   /* lock byte range */
#define SMBunlock     0x0D   /* unlock byte range */
#define SMBctemp      0x0E   /* create temporary file */
#define SMBmknew      0x0F   /* make new file */
#define SMBchkpth     0x10   /* check directory path */
#define SMBexit       0x11   /* process exit */
#define SMBlseek      0x12   /* seek */
#define SMBtcon       0x70   /* tree connect */
#define SMBtconX      0x75   /* tree connect and X*/
#define SMBtdis       0x71   /* tree disconnect */
#define SMBnegprot    0x72   /* negotiate protocol */
#define SMBdskattr    0x80   /* get disk attributes */
#define SMBsearch     0x81   /* search directory */
#define SMBsplopen    0xC0   /* open print spool file */
#define SMBsplwr      0xC1   /* write to print spool file */
#define SMBsplclose   0xC2   /* close print spool file */
#define SMBsplretq    0xC3   /* return print queue */
#define SMBsends      0xD0   /* send single block message */
#define SMBsendb      0xD1   /* send broadcast message */
#define SMBfwdname    0xD2   /* forward user name */
#define SMBcancelf    0xD3   /* cancel forward */
#define SMBgetmac     0xD4   /* get machine name */
#define SMBsendstrt   0xD5   /* send start of multi-block message */
#define SMBsendend    0xD6   /* send end of multi-block message */
#define SMBsendtxt    0xD7   /* send text of multi-block message */

/* Core+ protocol */
#define SMBlockread	  0x13   /* Lock a range and read */
#define SMBwriteunlock 0x14 /* Unlock a range then write */
#define SMBreadbraw   0x1a  /* read a block of data with no smb header */
#define SMBwritebraw  0x1d  /* write a block of data with no smb header */
#define SMBwritec     0x20  /* secondary write request */
#define SMBwriteclose 0x2c  /* write a file then close it */

/* dos extended protocol */
#define SMBreadBraw      0x1A   /* read block raw */
#define SMBreadBmpx      0x1B   /* read block multiplexed */
#define SMBreadBs        0x1C   /* read block (secondary response) */
#define SMBwriteBraw     0x1D   /* write block raw */
#define SMBwriteBmpx     0x1E   /* write block multiplexed */
#define SMBwriteBs       0x1F   /* write block (secondary request) */
#define SMBwriteC        0x20   /* write complete response */
#define SMBsetattrE      0x22   /* set file attributes expanded */
#define SMBgetattrE      0x23   /* get file attributes expanded */
#define SMBlockingX      0x24   /* lock/unlock byte ranges and X */
#define SMBtrans         0x25   /* transaction - name, bytes in/out */
#define SMBtranss        0x26   /* transaction (secondary request/response) */
#define SMBioctl         0x27   /* IOCTL */
#define SMBioctls        0x28   /* IOCTL  (secondary request/response) */
#define SMBcopy          0x29   /* copy */
#define SMBmove          0x2A   /* move */
#define SMBecho          0x2B   /* echo */
#define SMBopenX         0x2D   /* open and X */
#define SMBreadX         0x2E   /* read and X */
#define SMBwriteX        0x2F   /* write and X */
#define SMBsesssetupX    0x73   /* Session Set Up & X (including User Logon) */
#define SMBffirst        0x82   /* find first */
#define SMBfunique       0x83   /* find unique */
#define SMBfclose        0x84   /* find close */
#define SMBinvalid       0xFE   /* invalid command */

/* Extended 2.0 protocol */
#define SMBtrans2        0x32   /* TRANS2 protocol set */
#define SMBtranss2       0x33   /* TRANS2 protocol set, secondary command */
#define SMBfindclose     0x34   /* Terminate a TRANSACT2_FINDFIRST */
#define SMBfindnclose    0x35   /* Terminate a TRANSACT2_FINDNOTIFYFIRST */
#define SMBulogoffX      0x74   /* user logoff */


/* these are the TRANS2 sub commands */
#define TRANSACT2_OPEN          0
#define TRANSACT2_FINDFIRST     1
#define TRANSACT2_FINDNEXT      2
#define TRANSACT2_QFSINFO       3
#define TRANSACT2_SETFSINFO     4
#define TRANSACT2_QPATHINFO     5
#define TRANSACT2_SETPATHINFO   6
#define TRANSACT2_QFILEINFO     7
#define TRANSACT2_SETFILEINFO   8
#define TRANSACT2_FSCTL         9
#define TRANSACT2_IOCTL           10
#define TRANSACT2_FINDNOTIFYFIRST 11
#define TRANSACT2_FINDNOTIFYNEXT  12
#define TRANSACT2_MKDIR           13


/* these are the trans2 sub fields for primary requests */
#define smb_tpscnt smb_vwv0
#define smb_tdscnt smb_vwv1
#define smb_mprcnt smb_vwv2
#define smb_mdrcnt smb_vwv3
#define smb_msrcnt smb_vwv4
#define smb_flags smb_vwv5
#define smb_timeout smb_vwv6
#define smb_pscnt smb_vwv9
#define smb_psoff smb_vwv10
#define smb_dscnt smb_vwv11
#define smb_dsoff smb_vwv12
#define smb_suwcnt smb_vwv13
#define smb_setup smb_vwv14
#define smb_setup0 smb_setup
#define smb_setup1 (smb_setup+2)
#define smb_setup2 (smb_setup+4)

/* these are for the secondary requests */
#define smb_spscnt smb_vwv2
#define smb_spsoff smb_vwv3
#define smb_spsdisp smb_vwv4
#define smb_sdscnt smb_vwv5
#define smb_sdsoff smb_vwv6
#define smb_sdsdisp smb_vwv7
#define smb_sfid smb_vwv8

/* and these for responses */
#define smb_tprcnt smb_vwv0
#define smb_tdrcnt smb_vwv1
#define smb_prcnt smb_vwv3
#define smb_proff smb_vwv4
#define smb_prdisp smb_vwv5
#define smb_drcnt smb_vwv6
#define smb_droff smb_vwv7
#define smb_drdisp smb_vwv8

/* where to find the base of the SMB packet proper */
#define smb_base(buf) (((char *)(buf))+4)


#define SUCCESS 0    /* The request was successful. */
#define ERRDOS 0x01  /*  Error is from the core DOS operating system set. */
#define ERRSRV 0x02  /* Error is generated by the server network file manager.*/
#define ERRHRD 0x03  /* Error is an hardware error. */
#define ERRCMD 0xFF  /* Command was not in the "SMB" format. */

/* structure used to hold the incoming hosts info */
struct from_host {
    char   *name;			/* host name */
    char   *addr;			/* host address */
    struct sockaddr_in *sin;		/* their side of the link */
};

#define MAX_DGRAM_SIZE 576
#define MIN_DGRAM_SIZE 12

#define NMB_PORT 137
#define DGRAM_PORT 138
#define SMB_PORT 139

enum name_source {LMHOSTS, REGISTER, SELF, DNS, DNSFAIL};
enum node_type {B_NODE=0, P_NODE=1, M_NODE=2, NBDD_NODE=3};
enum packet_type {NMB_PACKET, DGRAM_PACKET};

/* a netbios name structure */
struct nmb_name {
  char name[17];
  char scope[64];
  int name_type;
};

/* a resource record */
struct res_rec {
  struct nmb_name rr_name;
  int rr_type;
  int rr_class;
  int ttl;
  int rdlength;
  char rdata[MAX_DGRAM_SIZE];
};

/* define a nmb packet. */
struct nmb_packet
{
  struct {
    int name_trn_id;
    int opcode;
    BOOL response;
    struct {
      BOOL bcast;
      BOOL recursion_available;
      BOOL recursion_desired;
      BOOL trunc;
      BOOL authoritative;
    } nm_flags;
    int rcode;
    int qdcount;
    int ancount;
    int nscount;
    int arcount;
  } header;

  struct {
    struct nmb_name question_name;
    int question_type;
    int question_class;
  } question;

  struct res_rec *answers;
  struct res_rec *nsrecs;
  struct res_rec *additional;
};

/* rfc1191 */
struct mtu_discovery {
	short unused;
	short nexthopmtu;
};

#define EXTRACT_SHORT(p)	((u_short)ntohs(*(u_short *)p))
#define EXTRACT_LONG(p)		(ntohl(*(u_int32 *)p))


/* pulled from tcpdump */
/* XXX probably should use getservbyname() and cache answers */
#define TFTP_PORT 69		/*XXX*/
#define NAMESERVER_PORT 53
#define KERBEROS_PORT 88	/*XXX*/
#define SUNRPC_PORT 111		/*XXX*/
#define SNMP_PORT 161		/*XXX*/
#define NTP_PORT 123		/*XXX*/
#define SNMPTRAP_PORT 162	/*XXX*/
#define RIP_PORT 520		/*XXX*/
#define KERBEROS_SEC_PORT 750	/*XXX*/


/* TICK_TIME in ms
 * time to wait between Read Requests
 * if no packet has been sniffed..
 */
#define TICK_TIME 10
#define OUR_IP	(gOurIP ? gOurIP : rkGetOurIP())
#define OUR_MAC (gOurMAC ? gOurMAC : rkGetOurMAC())
#define MAXHOSTNAMELEN	64	/* max length of hostname */

typedef struct _RIPDERM { 
	char *mBuf;
	int mLen;
} RIPDERM, *PRIPDERM;



//typedef list<PRIPDERM> VRIP;
//typedef list<char *> NAMELIST;
//typedef map<unsigned long, NAMELIST *> LMHOSTLIST;
//typedef map<unsigned long, __int64> MACMAP; /* note that masking is required */

//void SendThruFilterRaw(const char * p, int len);
//void SendHex(char *theAsciiString);
//void SendRaw(const char * theData, int theLen);
