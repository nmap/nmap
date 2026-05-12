/***************************************************************************
 * packettrace.cc                                                              *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2026 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and
 * add new features. You are highly encouraged to submit your changes as a
 * Github PR or by email to the dev@nmap.org mailing list for possible
 * incorporation into the main distribution. Unless you specify otherwise, it
 * is understood that you are offering us very broad rights to use your
 * submissions as described in the Nmap Public Source License Contributor
 * Agreement. This is important because we fund the project by selling licenses
 * with various terms, and also because the inability to relicense code has
 * caused devastating problems for other Free Software projects (such as KDE
 * and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

#if HAVE_CONFIG_H
#include "../nmap_config.h"
#endif

#include "nbase.h"

#include "netutil.h"

#include <assert.h>
#include <stddef.h>

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

static const char *nexthdrtoa(u8 nextheader, int acronym){

#define HDRTOA(num, short_name, long_name) \
  case num: \
    return (acronym ? short_name : long_name);\
    break;

switch(nextheader){
  /* Generate these lines from nmap-protocols using the following perl command:
   perl -lne'if(/^(\S+)\s*(\d+)\s*\#?\s*(.*)/){my$l=$3||$1;print qq{HDRTOA($2, "$1", "$l")}}'
  */
  HDRTOA(0, "hopopt", "IPv6 Hop-by-Hop Option")
  HDRTOA(1, "icmp", "Internet Control Message")
  HDRTOA(2, "igmp", "Internet Group Management")
  HDRTOA(3, "ggp", "Gateway-to-Gateway")
  HDRTOA(4, "ipv4", "IP in IP (encapsulation)")
  HDRTOA(5, "st", "Stream")
  HDRTOA(6, "tcp", "Transmission Control")
  HDRTOA(7, "cbt", "CBT")
  HDRTOA(8, "egp", "Exterior Gateway Protocol")
  HDRTOA(9, "igp", "any private interior gateway")
  HDRTOA(10, "bbn-rcc-mon", "BBN RCC Monitoring")
  HDRTOA(11, "nvp-ii", "Network Voice Protocol")
  HDRTOA(12, "pup", "PARC universal packet protocol")
  HDRTOA(13, "argus", "ARGUS")
  HDRTOA(14, "emcon", "EMCON")
  HDRTOA(15, "xnet", "Cross Net Debugger")
  HDRTOA(16, "chaos", "Chaos")
  HDRTOA(17, "udp", "User Datagram")
  HDRTOA(18, "mux", "Multiplexing")
  HDRTOA(19, "dcn-meas", "DCN Measurement Subsystems")
  HDRTOA(20, "hmp", "Host Monitoring")
  HDRTOA(21, "prm", "Packet Radio Measurement")
  HDRTOA(22, "xns-idp", "XEROX NS IDP")
  HDRTOA(23, "trunk-1", "Trunk-1")
  HDRTOA(24, "trunk-2", "Trunk-2")
  HDRTOA(25, "leaf-1", "Leaf-1")
  HDRTOA(26, "leaf-2", "Leaf-2")
  HDRTOA(27, "rdp", "Reliable Data Protocol")
  HDRTOA(28, "irtp", "Internet Reliable Transaction")
  HDRTOA(29, "iso-tp4", "ISO Transport Protocol Class 4")
  HDRTOA(30, "netblt", "Bulk Data Transfer Protocol")
  HDRTOA(31, "mfe-nsp", "MFE Network Services Protocol")
  HDRTOA(32, "merit-inp", "MERIT Internodal Protocol")
  HDRTOA(33, "dccp", "Datagram Congestion Control Protocol")
  HDRTOA(34, "3pc", "Third Party Connect Protocol")
  HDRTOA(35, "idpr", "Inter-Domain Policy Routing Protocol")
  HDRTOA(36, "xtp", "XTP")
  HDRTOA(37, "ddp", "Datagram Delivery Protocol")
  HDRTOA(38, "idpr-cmtp", "IDPR Control Message Transport Proto")
  HDRTOA(39, "tp++", "TP+")
  HDRTOA(40, "il", "IL Transport Protocol")
  HDRTOA(41, "ipv6", "Ipv6")
  HDRTOA(42, "sdrp", "Source Demand Routing Protocol")
  HDRTOA(43, "ipv6-route", "Routing Header for IPv6")
  HDRTOA(44, "ipv6-frag", "Fragment Header for IPv6")
  HDRTOA(45, "idrp", "Inter-Domain Routing Protocol")
  HDRTOA(46, "rsvp", "Reservation Protocol")
  HDRTOA(47, "gre", "General Routing Encapsulation")
  HDRTOA(48, "dsp", "Dynamic Source Routing Protocol. Historically MHRP")
  HDRTOA(49, "bna", "BNA")
  HDRTOA(50, "esp", "Encap Security Payload")
  HDRTOA(51, "ah", "Authentication Header")
  HDRTOA(52, "i-nlsp", "Integrated Net Layer Security  TUBA")
  HDRTOA(53, "swipe", "IP with Encryption")
  HDRTOA(54, "narp", "NBMA Address Resolution Protocol")
  HDRTOA(55, "mobile", "IP Mobility")
  HDRTOA(56, "tlsp", "Transport Layer Security Protocol using Kryptonet key management")
  HDRTOA(57, "skip", "SKIP")
  HDRTOA(58, "ipv6-icmp", "ICMP for IPv6")
  HDRTOA(59, "ipv6-nonxt", "No Next Header for IPv6")
  HDRTOA(60, "ipv6-opts", "Destination Options for IPv6")
  HDRTOA(61, "anyhost", "any host internal protocol")
  HDRTOA(62, "cftp", "CFTP")
  HDRTOA(63, "anylocalnet", "any local network")
  HDRTOA(64, "sat-expak", "SATNET and Backroom EXPAK")
  HDRTOA(65, "kryptolan", "Kryptolan")
  HDRTOA(66, "rvd", "MIT Remote Virtual Disk Protocol")
  HDRTOA(67, "ippc", "Internet Pluribus Packet Core")
  HDRTOA(68, "anydistribfs", "any distributed file system")
  HDRTOA(69, "sat-mon", "SATNET Monitoring")
  HDRTOA(70, "visa", "VISA Protocol")
  HDRTOA(71, "ipcv", "Internet Packet Core Utility")
  HDRTOA(72, "cpnx", "Computer Protocol Network Executive")
  HDRTOA(73, "cphb", "Computer Protocol Heart Beat")
  HDRTOA(74, "wsn", "Wang Span Network")
  HDRTOA(75, "pvp", "Packet Video Protocol")
  HDRTOA(76, "br-sat-mon", "Backroom SATNET Monitoring")
  HDRTOA(77, "sun-nd", "SUN ND PROTOCOL-Temporary")
  HDRTOA(78, "wb-mon", "WIDEBAND Monitoring")
  HDRTOA(79, "wb-expak", "WIDEBAND EXPAK")
  HDRTOA(80, "iso-ip", "ISO Internet Protocol")
  HDRTOA(81, "vmtp", "VMTP")
  HDRTOA(82, "secure-vmtp", "SECURE-VMTP")
  HDRTOA(83, "vines", "VINES")
  HDRTOA(84, "iptm", "Internet Protocol Traffic Manager. Historically TTP")
  HDRTOA(85, "nsfnet-igp", "NSFNET-IGP")
  HDRTOA(86, "dgp", "Dissimilar Gateway Protocol")
  HDRTOA(87, "tcf", "TCF")
  HDRTOA(88, "eigrp", "EIGRP")
  HDRTOA(89, "ospfigp", "OSPFIGP")
  HDRTOA(90, "sprite-rpc", "Sprite RPC Protocol")
  HDRTOA(91, "larp", "Locus Address Resolution Protocol")
  HDRTOA(92, "mtp", "Multicast Transport Protocol")
  HDRTOA(93, "ax.25", "AX.")
  HDRTOA(94, "ipip", "IP-within-IP Encapsulation Protocol")
  HDRTOA(95, "micp", "Mobile Internetworking Control Pro.")
  HDRTOA(96, "scc-sp", "Semaphore Communications Sec.")
  HDRTOA(97, "etherip", "Ethernet-within-IP Encapsulation")
  HDRTOA(98, "encap", "Encapsulation Header")
  HDRTOA(99, "anyencrypt", "any private encryption scheme")
  HDRTOA(100, "gmtp", "GMTP")
  HDRTOA(101, "ifmp", "Ipsilon Flow Management Protocol")
  HDRTOA(102, "pnni", "PNNI over IP")
  HDRTOA(103, "pim", "Protocol Independent Multicast")
  HDRTOA(104, "aris", "ARIS")
  HDRTOA(105, "scps", "SCPS")
  HDRTOA(106, "qnx", "QNX")
  HDRTOA(107, "a/n", "Active Networks")
  HDRTOA(108, "ipcomp", "IP Payload Compression Protocol")
  HDRTOA(109, "snp", "Sitara Networks Protocol")
  HDRTOA(110, "compaq-peer", "Compaq Peer Protocol")
  HDRTOA(111, "ipx-in-ip", "IPX in IP")
  HDRTOA(112, "vrrp", "Virtual Router Redundancy Protocol")
  HDRTOA(113, "pgm", "PGM Reliable Transport Protocol")
  HDRTOA(114, "any0hop", "any 0-hop protocol")
  HDRTOA(115, "l2tp", "Layer Two Tunneling Protocol")
  HDRTOA(116, "ddx", "D-II Data Exchange")
  HDRTOA(117, "iatp", "Interactive Agent Transfer Protocol")
  HDRTOA(118, "stp", "Schedule Transfer Protocol")
  HDRTOA(119, "srp", "SpectraLink Radio Protocol")
  HDRTOA(120, "uti", "UTI")
  HDRTOA(121, "smp", "Simple Message Protocol")
  HDRTOA(122, "sm", "Simple Multicast Protocol")
  HDRTOA(123, "ptp", "Performance Transparency Protocol")
  HDRTOA(124, "isis-ipv4", "ISIS over IPv4")
  HDRTOA(125, "fire", "fire")
  HDRTOA(126, "crtp", "Combat Radio Transport Protocol")
  HDRTOA(127, "crudp", "Combat Radio User Datagram")
  HDRTOA(128, "sscopmce", "sscopmce")
  HDRTOA(129, "iplt", "iplt")
  HDRTOA(130, "sps", "Secure Packet Shield")
  HDRTOA(131, "pipe", "Private IP Encapsulation within IP")
  HDRTOA(132, "sctp", "Stream Control Transmission Protocol")
  HDRTOA(133, "fc", "Fibre Channel")
  HDRTOA(134, "rsvp-e2e-ignore", "rsvp-e2e-ignore")
  HDRTOA(135, "mobility-hdr", "Mobility Header")
  HDRTOA(136, "udplite", "UDP-Lite [RFC3828]")
  HDRTOA(137, "mpls-in-ip", "MPLS-in-IP [RFC4023]")
  HDRTOA(138, "manet", "MANET Protocols [RFC5498]")
  HDRTOA(139, "hip", "Host Identity Protocol")
  HDRTOA(140, "shim6", "Shim6 Protocol [RFC5533]")
  HDRTOA(141, "wesp", "Wrapped Encapsulating Security Payload")
  HDRTOA(142, "rohc", "Robust Header Compression")
  HDRTOA(143, "ethernet", "RFC 8986 Ethernet next-header")
  HDRTOA(144, "aggfrag", "AGGFRAG encapsulation payload for ESP [draft-ietf-ipsecme-iptfs-18]")
  HDRTOA(253, "experimental1", "Use for experimentation and testing")
  HDRTOA(254, "experimental2", "Use for experimentation and testing")
  default:
    break;

  } /* End of switch */


  return (acronym ? "unknown" : "Unknown protocol");

} /* End of nexthdrtoa() */

/* TODO: Needs refactoring */
static inline char* STRAPP(const char *fmt, ...) {
  static char buf[256];
  static int bp;
  int left = (int)sizeof(buf)-bp;
  if(!fmt){
    bp = 0;
    return(buf);
  }
  if (left <= 0)
    return buf;
  va_list ap;
  va_start(ap, fmt);
  bp += Vsnprintf (buf+bp, left, fmt, ap);
  va_end(ap);

  return(buf);
}

/* TODO: Needs refactoring */
#define HEXDUMP -2
#define UNKNOWN -1

#define BREAK()		\
	{option_type = HEXDUMP; break;}
#define CHECK(tt)	\
  if(tt >= option_end)	\
  	{option_type = HEXDUMP; break;}

/* Takes binary data found in the IP Options field of an IPv4 packet
 * and returns a string containing an ASCII description of the options
 * found. The function returns a pointer to a static buffer that
 * subsequent calls will overwrite. On error, NULL is returned. */
char *format_ip_options(const u8* ipopt, int ipoptlen) {
  char ipstring[32];
  int option_type = UNKNOWN;// option type
  int option_len  = 0; // option length
  int option_pt   = 0; // option pointer
  int option_fl   = 0;  // option flag
  const u8 *tptr;	// temp pointer
  u32 *tint;		// temp int

  int option_sta = 0;	// option start offset
  int option_end = 0;	// option end offset
  int pt = 0;		// current offset

  // clear buffer
  STRAPP(NULL,NULL);

  if(!ipoptlen)
    return(NULL);

  while(pt<ipoptlen){	// for every char in ipopt
    // read ip option header
    if(option_type == UNKNOWN) {
      option_sta  = pt;
      option_type = ipopt[pt++];
      if(option_type != 0 && option_type != 1) { // should we be interested in length field?
        if(pt >= ipoptlen)	// no more chars
          {option_type = HEXDUMP;pt--; option_end = 255; continue;} // no length field, hex dump to the end
        option_len  = ipopt[pt++];
        // end must not be greater than length
        option_end  = MIN(option_sta + option_len, ipoptlen);
        // end must not be smaller than current position
        option_end  = MAX(option_end, option_sta+2);
      }
    }
    switch(option_type) {
    case 0:	// IPOPT_END
    	STRAPP(" EOL", NULL);
    	option_type = UNKNOWN;
  	break;
    case 1:	// IPOPT_NOP
    	STRAPP(" NOP", NULL);
    	option_type = UNKNOWN;
  	break;
/*    case 130:	// IPOPT_SECURITY
    	option_type=-1;
  	break;*/
    case 131:	// IPOPT_LSRR	-> Loose Source and Record Route
    case 137:	// IPOPT_SSRR	-> Strict Source and Record Route
    case 7:	// IPOPT_RR	-> Record Route
	if(pt - option_sta == 2) {
    	  STRAPP(" %s%s{", (option_type==131)?"LS":(option_type==137)?"SS":"", "RR");
    	  // option pointer
    	  CHECK(pt);
    	  option_pt = ipopt[pt++];
    	  if(option_pt%4 != 0 || (option_sta + option_pt-1)>option_end || option_pt<4)	//bad or too big pointer
    	    STRAPP(" [bad ptr=%02i]", option_pt);
    	}
    	if(pt - option_sta > 2) { // ip's
    	  int i, s = (option_pt)%4;
    	  // if pointer is mangled, fix it. it's max 3 bytes wrong
    	  CHECK(pt+3);
    	  for(i=0; i<s; i++)
    	    STRAPP("\\x%02x", ipopt[pt++]);
    	  option_pt -= i;
    	  // okay, now we can start printing ip's
    	  CHECK(pt+3);
	  tptr = &ipopt[pt]; pt+=4;
	  if(inet_ntop(AF_INET, (char *) tptr, ipstring, sizeof(ipstring)) == NULL){
	    return NULL;
      }
    	  STRAPP("%c%s",(pt-3-option_sta)==option_pt?'#':' ', ipstring);
    	  if(pt == option_end)
    	    STRAPP("%s",(pt-option_sta)==(option_pt-1)?"#":""); // pointer in the end?
    	}else BREAK();
  	break;
    case 68:	// IPOPT_TS	-> Internet Timestamp
	if(pt - option_sta == 2){
	  STRAPP(" TM{");
    	  // pointer
    	  CHECK(pt);
    	  option_pt  = ipopt[pt++];
	  // bad or too big pointer
    	  if(option_pt%4 != 1 || (option_sta + option_pt-1)>option_end || option_pt<5)
    	    STRAPP(" [bad ptr=%02i]", option_pt);
    	  // flags + overflow
    	  CHECK(pt);
    	  option_fl  = ipopt[pt++];
    	  if((option_fl&0x0C) || (option_fl&0x03)==2)
    	    STRAPP(" [bad flags=\\x%01hhx]", option_fl&0x0F);
  	  STRAPP("[%i hosts not recorded]", option_fl>>4);
  	  option_fl &= 0x03;
	}
    	if(pt - option_sta > 2) {// ip's
    	  int i, s = (option_pt+3)%(option_fl==0?4:8);
    	  // if pointer is mangled, fix it. it's max 3 bytes wrong
    	  CHECK(pt+(option_fl==0?3:7));
    	  for(i=0; i<s; i++)
    	    STRAPP("\\x%02x", ipopt[pt++]);
    	  option_pt-=i;

	  // print pt
  	  STRAPP("%c",(pt+1-option_sta)==option_pt?'#':' ');
    	  // okay, first grab ip.
    	  if(option_fl!=0){
    	    CHECK(pt+3);
	    tptr = &ipopt[pt]; pt+=4;
	    if(inet_ntop(AF_INET, (char *) tptr, ipstring, sizeof(ipstring)) == NULL){
	      return NULL;
        }
	    STRAPP("%s@", ipstring);
    	  }
    	  CHECK(pt+3);
	  tint = (u32*)&ipopt[pt]; pt+=4;
	  STRAPP("%lu", (unsigned long) ntohl(*tint));

    	  if(pt == option_end)
  	    STRAPP("%s",(pt-option_sta)==(option_pt-1)?"#":" ");
    	}else BREAK();
  	break;
    case 136:	// IPOPT_SATID	-> (SANET) Stream Identifier
	if(pt - option_sta == 2){
	  u16 *sh;
    	  STRAPP(" SI{",NULL);
    	  // length
    	  if(option_sta+option_len > ipoptlen || option_len!=4)
    	    STRAPP("[bad len %02i]", option_len);

    	  // stream id
    	  CHECK(pt+1);
    	  sh = (u16*) &ipopt[pt]; pt+=2;
    	  option_pt  = ntohs(*sh);
    	  STRAPP("id=%hu", (unsigned short) option_pt);
    	  if(pt != option_end)
    	    BREAK();
	}else BREAK();
  	break;
    case UNKNOWN:
    default:
    	// we read option_type and option_len, print them.
    	STRAPP(" ??{\\x%02hhx\\x%02hhx", option_type, option_len);
    	// check option_end once more:
    	if(option_len < ipoptlen)
    	  option_end = MIN(MAX(option_sta+option_len, option_sta+2),ipoptlen);
    	else
    	  option_end = 255;
    	option_type = HEXDUMP;
    	break;
    case HEXDUMP:
    	assert(pt<=option_end);
    	if(pt == option_end){
	  STRAPP("}",NULL);
    	  option_type=-1;
    	  break;
    	}
	STRAPP("\\x%02hhx", ipopt[pt++]);
    	break;
    }
    if(pt == option_end && option_type != UNKNOWN) {
      STRAPP("}",NULL);
      option_type = UNKNOWN;
    }
  } // while
  if(option_type != UNKNOWN)
    STRAPP("}");

  return(STRAPP("",NULL));
}
#undef CHECK
#undef BREAK
#undef UNKNOWN
#undef HEXDUMP


/* Returns a buffer of ASCII information about an IP packet that may
 * look like "TCP 127.0.0.1:50923 > 127.0.0.1:3 S ttl=61 id=39516
 * iplen=40 seq=625950769" or "ICMP PING (0/1) ttl=61 id=39516 iplen=40".
 * Returned buffer is static so it is NOT safe to call this in
 * multi-threaded environments without appropriate sync protection, or
 * call it twice in the same sentence (eg: as two printf parameters).
 * Obviously, the caller should never attempt to free() the buffer. The
 * returned buffer is guaranteed to be NULL-terminated but no
 * assumptions should be made concerning its length.
 *
 * The function knows IPv4, IPv6, TCP, UDP, SCTP, ICMP, and ICMPv6.
 *
 * The output has three different levels of detail. Parameter "detail"
 * determines how verbose the output should be. It should take one of
 * the following values:
 *
 *    LOW_DETAIL    (0x01): Traditional output.
 *    MEDIUM_DETAIL (0x02): More verbose than traditional.
 *    HIGH_DETAIL   (0x03): Contents of virtually every field of the
 *                          protocol headers .
 */
const char *ippackethdrinfo(const u8 *packet, u32 len, int detail) {
  struct abstract_ip_hdr hdr;
  const u8 *data;
  unsigned int datalen;

  static char protoinfo[1024] = "";     /* Stores final info string.         */
  char ipinfo[512] = "";                /* Temp info about IP.               */
  char icmpinfo[512] = "";              /* Temp info about ICMP.             */
  char icmptype[128] = "";              /* Temp info about ICMP type & code  */
  char icmpfields[256] = "";            /* Temp info for various ICMP fields */
  char fragnfo[64] = "";                /* Temp info about fragmentation.    */
  char srchost[INET6_ADDRSTRLEN] = "";  /* Src IP in dot-decimal notation.   */
  char dsthost[INET6_ADDRSTRLEN] = "";  /* Dst IP in dot-decimal notation.   */
  char *p = NULL;                       /* Aux pointer.                      */
  int frag_off = 0;                     /* To compute IP fragment offset.    */
  int more_fragments = 0;               /* True if IP MF flag is set.        */
  int dont_fragment = 0;                /* True if IP DF flag is set.        */
  int reserved_flag = 0;                /* True if IP Reserved flag is set.  */

  datalen = len;
  data = (u8 *) ip_get_data_any(packet, &datalen, &hdr);
  if (data == NULL)
    return "BOGUS!  Can't parse supposed IP packet";


  /* Ensure we end up with a valid detail number */
  if (detail != LOW_DETAIL && detail != MEDIUM_DETAIL && detail != HIGH_DETAIL)
    detail = LOW_DETAIL;

  /* IP INFORMATION ************************************************************/
  if (hdr.version == 4) { /* IPv4 */
    struct ip_hdr ip;
    memcpy(&ip, packet, sizeof(ip));
    const struct sockaddr_in *sin;

    /* Obtain IP source and destination info */
    sin = (struct sockaddr_in *) &hdr.src;
    inet_ntop(AF_INET, (void *)&sin->sin_addr.s_addr, srchost, sizeof(srchost));
    sin = (struct sockaddr_in *) &hdr.dst;
	inet_ntop(AF_INET, (void *)&sin->sin_addr.s_addr, dsthost, sizeof(dsthost));

    /* Compute fragment offset and check if flags are set */
    frag_off = 8 * (ntohs(ip.ip_off) & 8191) /* 2^13 - 1 */;
    more_fragments = ntohs(ip.ip_off) & IP_MF;
    dont_fragment = ntohs(ip.ip_off) & IP_DF;
    reserved_flag = ntohs(ip.ip_off) & IP_RF;

    /* Is this a fragmented packet? is it the last fragment? */
    if (frag_off || more_fragments) {
      Snprintf(fragnfo, sizeof(fragnfo), " frag offset=%d%s", frag_off, more_fragments ? "+" : "");
    }

    /* Create a string with information relevant to the specified level of detail */
    if (detail == LOW_DETAIL) {
      Snprintf(ipinfo, sizeof(ipinfo), "ttl=%d id=%hu iplen=%hu%s %s%s%s",
        ip.ip_ttl, (unsigned short) ntohs(ip.ip_id), (unsigned short) ntohs(ip.ip_len), fragnfo,
        ip.ip_hl==5?"":"ipopts={",
        ip.ip_hl==5?"":format_ip_options((u8*) packet + sizeof(struct ip_hdr), MIN((unsigned)(ip.ip_hl-5)*4,len-sizeof(struct ip_hdr))),
        ip.ip_hl==5?"":"}");
    } else if (detail == MEDIUM_DETAIL) {
      Snprintf(ipinfo, sizeof(ipinfo), "ttl=%d id=%hu proto=%d csum=0x%04x iplen=%hu%s %s%s%s",
        ip.ip_ttl, (unsigned short) ntohs(ip.ip_id),
        ip.ip_p, ntohs(ip.ip_sum),
        (unsigned short) ntohs(ip.ip_len), fragnfo,
        ip.ip_hl==5?"":"ipopts={",
        ip.ip_hl==5?"":format_ip_options((u8*) packet + sizeof(struct ip_hdr), MIN((unsigned)(ip.ip_hl-5)*4,len-sizeof(struct ip_hdr))),
        ip.ip_hl==5?"":"}");
    } else if (detail == HIGH_DETAIL) {
      Snprintf(ipinfo, sizeof(ipinfo), "ver=%d ihl=%d tos=0x%02x iplen=%hu id=%hu%s%s%s%s foff=%d%s ttl=%d proto=%d csum=0x%04x%s%s%s",
        ip.ip_v, ip.ip_hl,
        ip.ip_tos, (unsigned short) ntohs(ip.ip_len),
        (unsigned short) ntohs(ip.ip_id),
        (reserved_flag||dont_fragment||more_fragments) ? " flg=" : "",
        (reserved_flag)? "x" : "",
        (dont_fragment)? "D" : "",
        (more_fragments)? "M": "",
        frag_off, (more_fragments) ? "+" : "",
        ip.ip_ttl, ip.ip_p,
        ntohs(ip.ip_sum),
        ip.ip_hl==5?"":" ipopts={",
        ip.ip_hl==5?"":format_ip_options((u8*) packet + sizeof(struct ip_hdr), MIN((unsigned)(ip.ip_hl-5)*4,len-sizeof(struct ip_hdr))),
        ip.ip_hl==5?"":"}");
    }
  } else { /* IPv6 */
    struct ip6_hdr ip6;
    memcpy(&ip6, packet, sizeof(ip6));
    const struct sockaddr_in6 *sin6;

    /* Obtain IP source and destination info */
    sin6 = (struct sockaddr_in6 *) &hdr.src;
	inet_ntop(AF_INET6, (void *)sin6->sin6_addr.s6_addr, srchost, sizeof(srchost));
    sin6 = (struct sockaddr_in6 *) &hdr.dst;
	inet_ntop(AF_INET6, (void *)sin6->sin6_addr.s6_addr, dsthost, sizeof(dsthost));

    /* Obtain flow label and traffic class */
    u32 flow = ntohl(ip6.ip6_flow);
    u32 ip6_fl = flow & 0x000fffff;
    u32 ip6_tc = (flow & 0x0ff00000) >> 20;

    /* Create a string with information relevant to the specified level of detail */
    if (detail == LOW_DETAIL) {
      Snprintf(ipinfo, sizeof(ipinfo), "hopl=%d flow=%x payloadlen=%hu",
        ip6.ip6_hlim, ip6_fl, (unsigned short) ntohs(ip6.ip6_plen));
    } else if (detail == MEDIUM_DETAIL) {
      Snprintf(ipinfo, sizeof(ipinfo), "hopl=%d tclass=%d flow=%x payloadlen=%hu",
        ip6.ip6_hlim, ip6_tc, ip6_fl, (unsigned short) ntohs(ip6.ip6_plen));
    } else if (detail==HIGH_DETAIL) {
      Snprintf(ipinfo, sizeof(ipinfo), "ver=6, tclass=%x flow=%x payloadlen=%hu nh=%s hopl=%d ",
        ip6_tc, ip6_fl, (unsigned short) ntohs(ip6.ip6_plen),
        nexthdrtoa(ip6.ip6_nxt, 1), ip6.ip6_hlim);
    }
  }


  /* TCP INFORMATION ***********************************************************/
  if (hdr.proto == IPPROTO_TCP) {
    char tflags[10];
    char tcpinfo[64] = "";
    char buf[32];
    char tcpoptinfo[256] = "";
    struct tcp_hdr tcp;

    /* Let's parse the TCP header. The following code is very ugly because we
     * have to deal with a lot of different situations. We don't want to
     * segfault so we have to check every length and every bound to ensure we
     * don't read past the packet. We cannot even trust the contents of the
     * received packet because, for example, an IPv4 header may state it
     * carries a TCP packet but may actually carry nothing at all.
     *
     * So we distinguish 4 situations. I know the first two are weird but they
     * were there when I modified this code so I left them there just in
     * case.
     *      1. IP datagram is very small or is a fragment where we are missing
     *         the first part of the TCP header
     *      2. IP datagram is a fragment and although we are missing the first
     *         8 bytes of the TCP header, we have the rest of it (or some of
     *         the rest of it)
     *      3. IP datagram is NOT a fragment but we don't have the full TCP
     *         header, we are missing some bytes.
     *      4. IP datagram is NOT a fragment and we have at least a full 20
     *         byte TCP header.
     */

    /* CASE 1: where we don't have the first 8 bytes of the TCP header because
     * either the fragment belongs to somewhere past that or the IP contains
     * less than 8 bytes. This also includes empty IP packets that say they
     * contain a TCP packet. */
    if (frag_off > 8 || datalen < 8) {
      Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? ?? %s (incomplete)",
          srchost, dsthost, ipinfo);
    }
    /* For all cases after this, datalen is necessarily >= 8 and frag_off is <= 8 */

    /* CASE 2: where we are missing the first 8 bytes of the TCP header but we
     * have, at least, the next 8 bytes so we can see the ACK number, the
     * flags and window size. */
    else if (frag_off > 0) {
      /* Fragmentation is on 8-byte boundaries, so 8 is the only legal value here. */
      assert(frag_off == 8);
      memcpy((u8 *)&tcp + frag_off, data - frag_off, sizeof(tcp) - frag_off);

      /* TCP Flags */
      p = tflags;
      /* These are basically in tcpdump order */
      if (tcp.th_flags & TH_SYN)
        *p++ = 'S';
      if (tcp.th_flags & TH_FIN)
        *p++ = 'F';
      if (tcp.th_flags & TH_RST)
        *p++ = 'R';
      if (tcp.th_flags & TH_PUSH)
        *p++ = 'P';
      if (tcp.th_flags & TH_ACK) {
        *p++ = 'A';
        Snprintf(tcpinfo, sizeof(tcpinfo), " ack=%lu",
          (unsigned long) ntohl(tcp.th_ack));
      }
      if (tcp.th_flags & TH_URG)
        *p++ = 'U';
      if (tcp.th_flags & TH_ECE)
        *p++ = 'E'; /* rfc 2481/3168 */
      if (tcp.th_flags & TH_CWR)
        *p++ = 'C'; /* rfc 2481/3168 */
      *p++ = '\0';

      /* TCP Options */
      if ((u32) tcp.th_off * 4 > sizeof(struct tcp_hdr)) {
        if (datalen < (u32) tcp.th_off * 4 - frag_off) {
          Snprintf(tcpoptinfo, sizeof(tcpoptinfo), "option incomplete");
        } else {
          tcppacketoptinfo((u8*) data + sizeof(struct tcp_hdr),
            tcp.th_off*4 - sizeof(struct tcp_hdr),
            tcpoptinfo, sizeof(tcpoptinfo));
        }
      }

      /* Create a string with TCP information relevant to the specified level of detail */
      if (detail == LOW_DETAIL) { Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s %s %s %s",
          srchost, dsthost, tflags, ipinfo, tcpinfo, tcpoptinfo);
      } else if (detail == MEDIUM_DETAIL) {
        Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s ack=%lu win=%hu %s IP [%s]",
          srchost, dsthost, tflags,
          (unsigned long) ntohl(tcp.th_ack), (unsigned short) ntohs(tcp.th_win),
          tcpoptinfo, ipinfo);
      } else if (detail == HIGH_DETAIL) {
        if (datalen >= 12) { /* We have at least bytes 8-20 */
          Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:?? > %s:?? %s seq=%lu ack=%lu off=%d res=%d win=%hu csum=0x%04X urp=%hu%s%s] IP [%s]",
            srchost, dsthost, tflags,
            (unsigned long) ntohl(tcp.th_seq),
            (unsigned long) ntohl(tcp.th_ack),
            (u8)tcp.th_off, (u8)tcp.th_x2, (unsigned short) ntohs(tcp.th_win),
            ntohs(tcp.th_sum), (unsigned short) ntohs(tcp.th_urp),
            (tcpoptinfo[0]!='\0') ? " " : "",
            tcpoptinfo, ipinfo);
        } else { /* We only have bytes 8-16 */
          Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s ack=%lu win=%hu %s IP [%s]",
            srchost, dsthost, tflags,
            (unsigned long) ntohl(tcp.th_ack), (unsigned short) ntohs(tcp.th_win),
            tcpoptinfo, ipinfo);
        }
      }
    }
    /* For all cases after this, frag_off is necessarily 0 */

    /* CASE 3: where the IP packet is not a fragment but for some reason, we
     * don't have the entire TCP header, just part of it.*/
    else if (datalen < 20) {
      memcpy(&tcp, data, MIN(datalen, sizeof(tcp)));
      /* We know we have the first 8 bytes, so what's left? */
      /* We only have the first 64 bits: ports and seq number */
      if (datalen < 12) {
        Snprintf(tcpinfo, sizeof(tcpinfo), "TCP %s:%hu > %s:%hu ?? seq=%lu (incomplete) %s",
          srchost, (unsigned short) ntohs(tcp.th_sport), dsthost,
          (unsigned short) ntohs(tcp.th_dport), (unsigned long) ntohl(tcp.th_seq), ipinfo);
      }

      /* We only have the first 96 bits: ports, seq and ack number */
      else if (datalen < 16) {
        if (detail == LOW_DETAIL) { /* We don't print ACK in low detail */
          Snprintf(tcpinfo, sizeof(tcpinfo), "TCP %s:%hu > %s:%hu seq=%lu (incomplete), %s",
            srchost, (unsigned short) ntohs(tcp.th_sport), dsthost,
            (unsigned short) ntohs(tcp.th_dport), (unsigned long) ntohl(tcp.th_seq), ipinfo);
        } else {
          Snprintf(tcpinfo, sizeof(tcpinfo), "TCP [%s:%hu > %s:%hu seq=%lu ack=%lu (incomplete)] IP [%s]",
            srchost, (unsigned short) ntohs(tcp.th_sport), dsthost,
            (unsigned short) ntohs(tcp.th_dport), (unsigned long) ntohl(tcp.th_seq),
            (unsigned long) ntohl(tcp.th_ack), ipinfo);
        }
      }

      /* We are missing some part of the last 32 bits (checksum and urgent pointer) */
      else {
        p = tflags;
        /* These are basically in tcpdump order */
        if (tcp.th_flags & TH_SYN)
          *p++ = 'S';
        if (tcp.th_flags & TH_FIN)
          *p++ = 'F';
        if (tcp.th_flags & TH_RST)
          *p++ = 'R';
        if (tcp.th_flags & TH_PUSH)
          *p++ = 'P';
        if (tcp.th_flags & TH_ACK) {
          *p++ = 'A';
          Snprintf(buf, sizeof(buf), " ack=%lu",
            (unsigned long) ntohl(tcp.th_ack));
          strncat(tcpinfo, buf, sizeof(tcpinfo) - strlen(tcpinfo) - 1);
        }
        if (tcp.th_flags & TH_URG)
          *p++ = 'U';
        if (tcp.th_flags & TH_ECE)
          *p++ = 'E'; /* rfc 2481/3168 */
        if (tcp.th_flags & TH_CWR)
          *p++ = 'C'; /* rfc 2481/3168 */
        *p++ = '\0';


        /* Create a string with TCP information relevant to the specified level of detail */
        if (detail == LOW_DETAIL) { /* We don't print ACK in low detail */
          Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%hu > %s:%hu %s %s seq=%lu win=%hu (incomplete)",
            srchost, (unsigned short) ntohs(tcp.th_sport), dsthost, (unsigned short) ntohs(tcp.th_dport),
            tflags, ipinfo, (unsigned long) ntohl(tcp.th_seq),
            (unsigned short) ntohs(tcp.th_win));
        } else if (detail == MEDIUM_DETAIL) {
          Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%hu > %s:%hu %s seq=%lu ack=%lu win=%hu (incomplete)] IP [%s]",
            srchost, (unsigned short) ntohs(tcp.th_sport), dsthost, (unsigned short) ntohs(tcp.th_dport),
            tflags,  (unsigned long) ntohl(tcp.th_seq),
            (unsigned long) ntohl(tcp.th_ack),
            (unsigned short) ntohs(tcp.th_win), ipinfo);
        } else if (detail == HIGH_DETAIL) {
          Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%hu > %s:%hu %s seq=%lu ack=%lu off=%d res=%d win=%hu (incomplete)] IP [%s]",
            srchost, (unsigned short) ntohs(tcp.th_sport),
            dsthost, (unsigned short) ntohs(tcp.th_dport),
            tflags, (unsigned long) ntohl(tcp.th_seq),
            (unsigned long) ntohl(tcp.th_ack),
            (u8)tcp.th_off, (u8)tcp.th_x2, (unsigned short) ntohs(tcp.th_win),
            ipinfo);
        }
      }
    }

    /* CASE 4: where we (finally!) have a full 20 byte TCP header so we can
     * safely print all fields */
    else { /* if (datalen >= 20) */
      memcpy(&tcp, data, MIN(datalen, sizeof(tcp)));

      /* TCP Flags */
      p = tflags;
      /* These are basically in tcpdump order */
      if (tcp.th_flags & TH_SYN)
        *p++ = 'S';
      if (tcp.th_flags & TH_FIN)
        *p++ = 'F';
      if (tcp.th_flags & TH_RST)
        *p++ = 'R';
      if (tcp.th_flags & TH_PUSH)
        *p++ = 'P';
      if (tcp.th_flags & TH_ACK) {
        *p++ = 'A';
        Snprintf(buf, sizeof(buf), " ack=%lu",
            (unsigned long) ntohl(tcp.th_ack));
        strncat(tcpinfo, buf, sizeof(tcpinfo) - strlen(tcpinfo) - 1);
      }
      if (tcp.th_flags & TH_URG)
        *p++ = 'U';
      if (tcp.th_flags & TH_ECE)
        *p++ = 'E'; /* rfc 2481/3168 */
      if (tcp.th_flags & TH_CWR)
        *p++ = 'C'; /* rfc 2481/3168 */
      *p++ = '\0';

      /* TCP Options */
      if ((u32) tcp.th_off * 4 > sizeof(struct tcp_hdr)) {
        if (datalen < (unsigned int) tcp.th_off * 4) {
          Snprintf(tcpoptinfo, sizeof(tcpoptinfo), "option incomplete");
        } else {
          tcppacketoptinfo((u8*) data + sizeof(struct tcp_hdr),
            tcp.th_off*4 - sizeof(struct tcp_hdr),
            tcpoptinfo, sizeof(tcpoptinfo));
        }
      }

      /* Rest of header fields */
      if (detail == LOW_DETAIL) {
        Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%hu > %s:%hu %s %s seq=%lu win=%hu %s",
          srchost, (unsigned short) ntohs(tcp.th_sport), dsthost, (unsigned short) ntohs(tcp.th_dport),
          tflags, ipinfo, (unsigned long) ntohl(tcp.th_seq),
          (unsigned short) ntohs(tcp.th_win), tcpoptinfo);
      } else if (detail == MEDIUM_DETAIL) {
        Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%hu > %s:%hu %s seq=%lu win=%hu csum=0x%04X%s%s] IP [%s]",
          srchost, (unsigned short) ntohs(tcp.th_sport), dsthost, (unsigned short) ntohs(tcp.th_dport),
          tflags, (unsigned long) ntohl(tcp.th_seq),
          (unsigned short) ntohs(tcp.th_win),  (unsigned short) ntohs(tcp.th_sum),
          (tcpoptinfo[0]!='\0') ? " " : "",
          tcpoptinfo, ipinfo);
      } else if (detail == HIGH_DETAIL) {
        Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%hu > %s:%hu %s seq=%lu ack=%lu off=%d res=%d win=%hu csum=0x%04X urp=%hu%s%s] IP [%s]",
          srchost, (unsigned short) ntohs(tcp.th_sport),
          dsthost, (unsigned short) ntohs(tcp.th_dport),
          tflags, (unsigned long) ntohl(tcp.th_seq),
          (unsigned long) ntohl(tcp.th_ack),
          (u8)tcp.th_off, (u8)tcp.th_x2, (unsigned short) ntohs(tcp.th_win),
          ntohs(tcp.th_sum), (unsigned short) ntohs(tcp.th_urp),
          (tcpoptinfo[0]!='\0') ? " " : "",
          tcpoptinfo, ipinfo);
      }
    }

    /* UDP INFORMATION ***********************************************************/
  } else if (hdr.proto == IPPROTO_UDP &&
      (frag_off || datalen < sizeof(struct udp_hdr))) {
    Snprintf(protoinfo, sizeof(protoinfo), "UDP %s:?? > %s:?? fragment %s (incomplete)",
      srchost, dsthost, ipinfo);
  } else if (hdr.proto == IPPROTO_UDP) {
    struct udp_hdr udp;
    memcpy(&udp, data, sizeof(udp));

    if (detail == LOW_DETAIL) {
      Snprintf(protoinfo, sizeof(protoinfo), "UDP %s:%hu > %s:%hu %s",
          srchost, (unsigned short) ntohs(udp.uh_sport), dsthost, (unsigned short) ntohs(udp.uh_dport),
          ipinfo);
    } else if (detail == MEDIUM_DETAIL) {
      Snprintf(protoinfo, sizeof(protoinfo), "UDP [%s:%hu > %s:%hu csum=0x%04X] IP [%s]",
        srchost, (unsigned short) ntohs(udp.uh_sport), dsthost, (unsigned short) ntohs(udp.uh_dport), ntohs(udp.uh_sum),
        ipinfo);
    } else if (detail == HIGH_DETAIL) {
      Snprintf(protoinfo, sizeof(protoinfo), "UDP [%s:%hu > %s:%hu len=%hu csum=0x%04X] IP [%s]",
        srchost, (unsigned short) ntohs(udp.uh_sport), dsthost, (unsigned short) ntohs(udp.uh_dport),
        (unsigned short) ntohs(udp.uh_ulen), ntohs(udp.uh_sum),
        ipinfo);
    }

    /* SCTP INFORMATION **********************************************************/
  } else if (hdr.proto == IPPROTO_SCTP &&
      (frag_off || datalen < sizeof(struct sctp_hdr))) {
    Snprintf(protoinfo, sizeof(protoinfo), "SCTP %s:?? > %s:?? fragment %s (incomplete)",
      srchost, dsthost, ipinfo);
  } else if (hdr.proto == IPPROTO_SCTP) {
    struct sctp_hdr sctp;
    memcpy(&sctp, data, sizeof(sctp));

    if (detail == LOW_DETAIL) {
      Snprintf(protoinfo, sizeof(protoinfo), "SCTP %s:%hu > %s:%hu %s",
        srchost, (unsigned short) ntohs(sctp.sh_sport), dsthost, (unsigned short) ntohs(sctp.sh_dport),
        ipinfo);
    } else if (detail == MEDIUM_DETAIL) {
      Snprintf(protoinfo, sizeof(protoinfo), "SCTP [%s:%hu > %s:%hu csum=0x%08x] IP [%s]",
        srchost, (unsigned short) ntohs(sctp.sh_sport), dsthost, (unsigned short) ntohs(sctp.sh_dport), ntohl(sctp.sh_sum),
        ipinfo);
    } else if (detail == HIGH_DETAIL) {
      Snprintf(protoinfo, sizeof(protoinfo), "SCTP [%s:%hu > %s:%hu vtag=%lu csum=0x%08x] IP [%s]",
        srchost, (unsigned short) ntohs(sctp.sh_sport), dsthost, (unsigned short) ntohs(sctp.sh_dport),
        (unsigned long) ntohl(sctp.sh_vtag), ntohl(sctp.sh_sum),
        ipinfo);
    }

    /* ICMP INFORMATION **********************************************************/
  } else if (hdr.proto == IPPROTO_ICMP && frag_off) {
    Snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s fragment %s (incomplete)",
      srchost, dsthost, ipinfo);
  } else if (hdr.proto == IPPROTO_ICMP) {
    struct ip_hdr ip2;       /* Points to the IP datagram carried by some ICMP messages */
    char *ip2dst;         /* Dest IP in caried IP datagram                   */
    char auxbuff[128];    /* Aux buffer                                      */
    struct icmp_hdr icmp;
    unsigned pktlen = sizeof(icmp);

    /* We need the ICMP packet to be at least 8 bytes long */
    if (ICMP_LEN_MIN > datalen)
      goto icmpbad;

    memcpy(&icmp, data, sizeof(icmp));

    union icmp_msg msg;
    memcpy(&msg, data + pktlen, MIN(datalen - pktlen, sizeof(msg)));

    switch(icmp.icmp_type) {
      /* Echo Reply **************************/
      case 0:
        strcpy(icmptype, "Echo reply");
        Snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu", (unsigned short) ntohs(msg.echo.icmp_id), (unsigned short) ntohs(msg.echo.icmp_seq));
        break;

        /* Destination Unreachable *************/
      case 3:
        /* Point to the start of the original datagram */
        pktlen += offsetof(struct icmp_msg_quote, icmp_ip);
        if (datalen >= pktlen + sizeof(ip2)) {
          memcpy(&ip2, data + pktlen, sizeof(ip2));
          pktlen += ip2.ip_hl * 4;
        } else {
          pktlen += sizeof(ip2);
        }

        /* Check we have a full IP datagram included in the ICMP message */
        if (pktlen > datalen) {
          if (datalen == 8) {
            Snprintf(icmptype, sizeof icmptype, "Destination unreachable%s",
              (detail!=LOW_DETAIL)? " (original datagram missing)" : "");
          } else {
            Snprintf(icmptype, sizeof icmptype, "Destination unreachable%s",
              (detail!=LOW_DETAIL)? " (part of original datagram missing)" : "");
          }
          goto icmpbad;
        }

        /* Basic check to ensure we have an IPv4 datagram attached */
        /* TODO: We should actually check the datagram checksum to
         * see if it validates because just checking the version number
         * is not enough. On average, if we get random data 1 out of
         * 16 (2^4bits) times we will have value 4. */
        if ((ip2.ip_v != 4) || ((ip2.ip_hl * 4) < 20) || ((ip2.ip_hl * 4) > 60)) {
          Snprintf(icmptype, sizeof icmptype, "Destination unreachable (bogus original datagram)");
          goto icmpbad;
        }

        /* Determine the IP the original datagram was sent to */
        ip2dst = ip_ntoa(&ip2.ip_dst);

        /* Determine type of Destination unreachable from the code value */
        switch (icmp.icmp_code) {
          case 0:
            Snprintf(icmptype, sizeof icmptype, "Network %s unreachable", ip2dst);
            break;

          case 1:
            Snprintf(icmptype, sizeof icmptype, "Host %s unreachable", ip2dst);
            break;

          case 2:
            Snprintf(icmptype, sizeof icmptype, "Protocol %u unreachable", ip2.ip_p);
            break;

          case 3:
            if (pktlen + 8 < datalen) {
              /* We have the original datagram + the first 8 bytes of the
               * transport layer header */
              const u8 *pp = data + pktlen;
              int offset = -1;
              if (ip2.ip_p == IPPROTO_UDP)
                offset = offsetof(struct udp_hdr, uh_dport);
              else if (ip2.ip_p == IPPROTO_TCP)
                offset = offsetof(struct tcp_hdr, th_dport);
              else if (ip2.ip_p == IPPROTO_SCTP)
                offset = offsetof(struct sctp_hdr, sh_dport);

              if (offset >= 0) {
                pp += offset;
                Snprintf(icmptype, sizeof icmptype, "Port %hu unreachable", (u16)((pp[0] << 8) + pp[1]));
              }
              else
                Snprintf(icmptype, sizeof icmptype, "Port unreachable (unknown protocol %u)", ip2.ip_p);
            }
            else
              strcpy(icmptype, "Port unreachable");
            break;

          case 4:
            strcpy(icmptype, "Fragmentation required");
            Snprintf(icmpfields, sizeof(icmpfields), "Next-Hop-MTU=%d", ntohs(msg.needfrag.icmp_mtu));
            break;

          case 5:
            strcpy(icmptype, "Source route failed");
            break;

          case 6:
            Snprintf(icmptype, sizeof icmptype, "Destination network %s unknown", ip2dst);
            break;

          case 7:
            Snprintf(icmptype, sizeof icmptype, "Destination host %s unknown", ip2dst);
            break;

          case 8:
            strcpy(icmptype, "Source host isolated");
            break;

          case 9:
            Snprintf(icmptype, sizeof icmptype, "Destination network %s administratively prohibited", ip2dst);
            break;

          case 10:
            Snprintf(icmptype, sizeof icmptype, "Destination host %s administratively prohibited", ip2dst);
            break;

          case 11:
            Snprintf(icmptype, sizeof icmptype, "Network %s unreachable for TOS", ip2dst);
            break;

          case 12:
            Snprintf(icmptype, sizeof icmptype, "Host %s unreachable for TOS", ip2dst);
            break;

          case 13:
            strcpy(icmptype, "Communication administratively prohibited by filtering");
            break;

          case 14:
            strcpy(icmptype, "Host precedence violation");
            break;

          case 15:
            strcpy(icmptype, "Precedence cutoff in effect");
            break;

          default:
            strcpy(icmptype, "Destination unreachable (unknown code)");
            break;
        } /* End of ICMP Code switch */
        break;


        /* Source Quench ***********************/
      case 4:
        strcpy(icmptype, "Source quench");
        break;

        /* Redirect ****************************/
      case 5:
        if (icmp.icmp_code == 0)
          strcpy(icmptype, "Network redirect");
        else if (icmp.icmp_code == 1)
          strcpy(icmptype, "Host redirect");
        else
          strcpy(icmptype, "Redirect (unknown code)");
        inet_ntop(AF_INET, &msg.redirect.icmp_void, auxbuff, sizeof(auxbuff));
        Snprintf(icmpfields, sizeof(icmpfields), "addr=%s", auxbuff);
        break;

        /* Echo Request ************************/
      case 8:
        strcpy(icmptype, "Echo request");
        Snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu", (unsigned short) ntohs(msg.echo.icmp_id), (unsigned short) ntohs(msg.echo.icmp_seq));
        break;

        /* Router Advertisement ****************/
      case 9:
        if (icmp.icmp_code == 16)
          strcpy(icmptype, "Router advertisement (Mobile Agent Only)");
        else
          strcpy(icmptype, "Router advertisement");
        Snprintf(icmpfields, sizeof(icmpfields), "addrs=%u addrlen=%u lifetime=%hu",
          msg.rtradvert.icmp_num_addrs,
          msg.rtradvert.icmp_wpa,
          (unsigned short) ntohs(msg.rtradvert.icmp_lifetime));
        break;

        /* Router Solicitation *****************/
      case 10:
        strcpy(icmptype, "Router solicitation");
        break;

        /* Time Exceeded ***********************/
      case 11:
        if (icmp.icmp_code == 0)
          strcpy(icmptype, "TTL=0 during transit");
        else if (icmp.icmp_code == 1)
          strcpy(icmptype, "TTL=0 during reassembly");
        else
          strcpy(icmptype, "TTL exceeded (unknown code)");
        break;

        /* Parameter Problem *******************/
      case 12:
        if (icmp.icmp_code == 0)
          strcpy(icmptype, "Parameter problem (pointer indicates error)");
        else if (icmp.icmp_code == 1)
          strcpy(icmptype, "Parameter problem (option missing)");
        else if (icmp.icmp_code == 2)
          strcpy(icmptype, "Parameter problem (bad length)");
        else
          strcpy(icmptype, "Parameter problem (unknown code)");
        Snprintf(icmpfields, sizeof(icmpfields), "pointer=%hhu", *((u8 *)(&msg.paramprob.icmp_void)));
        break;

        /* Timestamp Request/Reply *************/
      case 13:
      case 14:
        Snprintf(icmptype, sizeof(icmptype), "Timestamp %s", (icmp.icmp_type == 13)? "request" : "reply");
        Snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu orig=%lu recv=%lu trans=%lu",
          (unsigned short) ntohs(msg.tstamp.icmp_id), (unsigned short) ntohs(msg.tstamp.icmp_seq),
          (unsigned long) ntohl(msg.tstamp.icmp_ts_orig),
          (unsigned long) ntohl(msg.tstamp.icmp_ts_rx),
          (unsigned long) ntohl(msg.tstamp.icmp_ts_tx));
        break;

        /* Information Request *****************/
      case 15:
        strcpy(icmptype, "Information request");
        Snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu", (unsigned short) ntohs(msg.info.icmp_id), (unsigned short) ntohs(msg.info.icmp_seq));
        break;

        /* Information Reply *******************/
      case 16:
        strcpy(icmptype, "Information reply");
        Snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu", (unsigned short) ntohs(msg.info.icmp_id), (unsigned short) ntohs(msg.info.icmp_seq));
        break;

        /* Netmask Request/Reply ***************/
      case 17:
      case 18:
        Snprintf(icmptype, sizeof(icmptype), "Address mask %s", (icmp.icmp_type == 17)? "request" : "reply");
        inet_ntop(AF_INET, &msg.mask.icmp_mask, auxbuff, sizeof(auxbuff));
        Snprintf(icmpfields, sizeof(icmpfields), "id=%u seq=%u mask=%s",
            (unsigned short) ntohs(msg.mask.icmp_id), (unsigned short) ntohs(msg.mask.icmp_seq), auxbuff);
        break;

        /* Traceroute **************************/
      case 30:
        strcpy(icmptype, "Traceroute");
        break;

        /* Domain Name Request *****************/
      case 37:
        strcpy(icmptype, "Domain name request");
        break;

        /* Domain Name Reply *******************/
      case 38:
        strcpy(icmptype, "Domain name reply");
        break;

        /* Security ****************************/
      case 40:
        strcpy(icmptype, "Security failures"); /* rfc 2521 */
        break;

      default:
        strcpy(icmptype, "Unknown type"); break;
        break;
    } /* End of ICMP Type switch */

    if (pktlen > datalen) {
icmpbad:
      if (icmptype[0] != '\0') {
        /* We still have this information */
        Snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s %s (type=%d/code=%d) %s",
            srchost, dsthost, icmptype, icmp.icmp_type, icmp.icmp_code, ipinfo);
      } else {
        Snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s [??] %s",
            srchost, dsthost, ipinfo);
      }
    } else {
      sprintf(icmpinfo,"type=%d/code=%d", icmp.icmp_type, icmp.icmp_code);

      Snprintf(protoinfo, sizeof(protoinfo), "ICMP [%s > %s %s (%s) %s] IP [%s]",
        srchost, dsthost, icmptype, icmpinfo, icmpfields, ipinfo);
    }

  } else if (hdr.proto == IPPROTO_ICMPV6) {
    if (datalen > sizeof(struct icmpv6_hdr)) {
      const struct icmpv6_hdr *icmpv6;

      icmpv6 = (struct icmpv6_hdr *) data;
      Snprintf(protoinfo, sizeof(protoinfo), "ICMPv6 (%d) %s > %s (type=%d/code=%d) %s",
          hdr.proto, srchost, dsthost,
          icmpv6->icmpv6_type, icmpv6->icmpv6_code, ipinfo);
    }
    else {
      Snprintf(protoinfo, sizeof(protoinfo), "ICMPv6 (%d) %s > %s (type=?/code=?) %s",
          hdr.proto, srchost, dsthost, ipinfo);
    }
  } else {
    /* UNKNOWN PROTOCOL **********************************************************/
    const char *hdrstr;

    hdrstr = nexthdrtoa(hdr.proto, 1);
    if (hdrstr == NULL || *hdrstr == '\0') {
      Snprintf(protoinfo, sizeof(protoinfo), "Unknown protocol (%d) %s > %s: %s",
        hdr.proto, srchost, dsthost, ipinfo);
    } else {
      Snprintf(protoinfo, sizeof(protoinfo), "%s (%d) %s > %s: %s",
        hdrstr, hdr.proto, srchost, dsthost, ipinfo);
    }
  }

  return protoinfo;
}

