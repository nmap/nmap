/***************************************************************************
 * netutil.h -- The main include file exposing the external API for        *
 * libnetutil, a library that provides network-related functions or        *
 * classes that make it easier to handle things like network interfaces,   *
 * routing tables, raw packet manipulation, etc. The lib was originally    *
 * written for use in the Nmap Security Scanner ( https://nmap.org ).       *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
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
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

/* $Id: netutil.h 18098 2010-06-14 11:50:12Z luis $ */

#ifndef _NETUTIL_H_
#define _NETUTIL_H_ 1

#ifdef __cplusplus
extern "C" {
#endif
#include <pcap.h>
#ifdef __cplusplus
}
#endif

#include "dnet.h"
#include <nbase.h>

/* It is VERY important to never change the value of these two constants.
 * Specially, OP_FAILURE should never be positive, as some pieces of code take
 * that for granted. */
enum { OP_FAILURE = -1, OP_SUCCESS = 0 };


/* For systems without SCTP in netinet/in.h, such as MacOS X or Win */
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

/* Container used for information common to IPv4 and IPv6 headers, used by
   ip_get_data. */
struct abstract_ip_hdr {
  u8 version; /* 4 or 6. */
  struct sockaddr_storage src;
  struct sockaddr_storage dst;
  u8 proto; /* IPv4 proto or IPv6 next header. */
  u8 ttl;   /* IPv4 TTL or IPv6 hop limit. */
  u32 ipid; /* IPv4 IP ID or IPv6 flow label. */
};

#if defined(__GNUC__)
#define NORETURN __attribute__((noreturn))
#elif defined(_MSC_VER)
#define NORETURN __declspec(noreturn)
#else
#define NORETURN
#endif

NORETURN void netutil_fatal(const char *str, ...)
     __attribute__ ((format (printf, 1, 2)));

int netutil_error(const char *str, ...)
     __attribute__ ((format (printf, 1, 2)));

/* This function converts zero-terminated 'txt' string to binary 'data'.
   It is used to parse user input for ip options. Some examples of possible input
   strings and results:
   	'\x01*2\xA2'	-> [0x01,0x01,0xA2]	// with 'x' number is parsed in hex
   	'\01\01\255'	-> [0x01,0x01,0xFF]	// without 'x' its in decimal
   	'\x01\x00*2'	-> [0x01,0x00,0x00]	// '*' is copying char
   	'R'		-> Record Route with 9 slots
   	'S 192.168.0.1 172.16.0.1' -> Strict Route with 2 slots
   	'L 192.168.0.1 172.16.0.1' -> Loose Route with 2 slots
   	'T'		-> Record Timestamp with 9 slots
   	'U'		-> Record Timestamp and Ip Address with 4 slots
   On success, the function returns the length of the final binary
   options stored in "data". In case of error, OP_FAILURE is returned
   and the "errstr" buffer is filled with an error message
   (unless it's NULL). Note that the returned error message does NOT
   contain a newline character at the end. */
int parse_ip_options(const char *txt, u8 *data, int datalen, int* firsthopoff, int* lasthopoff, char *errstr, size_t errstrlen);

/* Resolves the given hostname or IP address with getaddrinfo, and stores the
   first result (if any) in *ss and *sslen. The value of port will be set in the
   appropriate place in *ss; set to 0 if you don't care. af may be AF_UNSPEC, in
   which case getaddrinfo may return e.g. both IPv4 and IPv6 results; which one
   is first depends on the system configuration. Returns 0 on success, or a
   getaddrinfo return code (suitable for passing to gai_strerror) on failure.
   *ss and *sslen are always defined when this function returns 0. */
int resolve(const char *hostname, unsigned short port,
  struct sockaddr_storage *ss, size_t *sslen, int af);

/* As resolve, but do not do DNS resolution of hostnames; the first argument
   must be the string representation of a numeric IP address. */
int resolve_numeric(const char *ip, unsigned short port,
  struct sockaddr_storage *ss, size_t *sslen, int af);

/*
 * Returns 1 if this is a reserved IP address, where "reserved" means
 * either a private address, non-routable address, or even a non-reserved
 * but unassigned address which has an extremely high probability of being
 * black-holed.
 *
 * We try to optimize speed when ordering the tests. This optimization
 * assumes that all byte values are equally likely in the input.
 *
 * Warning: This function needs frequent attention because IANA has been
 * allocating address blocks many times per year (although it's questionable
 * how much longer this trend can be kept up).
 *
 * Check
 * <http://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.txt>
 * for the most recent assigments and
 * <http://www.cymru.com/Documents/bogon-bn-nonagg.txt> for bogon
 * netblocks.
 */
int ip_is_reserved(struct in_addr *ip);


/* A couple of trivial functions that maintain a cache of IP to MAC
 * Address entries. Function mac_cache_get() looks for the IPv4 address
 * in ss and fills in the 'mac' parameter and returns true if it is
 * found.  Otherwise (not found), the function returns false.
 * Function mac_cache_set() adds an entry with the given ip (ss) and
 * mac address.  An existing entry for the IP ss will be overwritten
 * with the new MAC address.  mac_cache_set() always returns true. */
int mac_cache_get(const struct sockaddr_storage *ss, u8 *mac);
int mac_cache_set(const struct sockaddr_storage *ss, u8 *mac);

const void *ip_get_data(const void *packet, unsigned int *len,
  struct abstract_ip_hdr *hdr);
const void *ip_get_data_any(const void *packet, unsigned int *len,
  struct abstract_ip_hdr *hdr);
/* Get the upper-layer protocol from an IPv4 packet. */
const void *ipv4_get_data(const struct ip *ip, unsigned int *len);
/* Get the upper-layer protocol from an IPv6 packet. This skips over known
   extension headers. The length of the upper-layer payload is stored in *len.
   The protocol is stored in *nxt. Returns NULL in case of error. */
const void *ipv6_get_data(const struct ip6_hdr *ip6, unsigned int *len, u8 *nxt);
const void *ipv6_get_data_any(const struct ip6_hdr *ip6, unsigned int *len, u8 *nxt);
const void *icmp_get_data(const struct icmp_hdr *icmp, unsigned int *len);
const void *icmpv6_get_data(const struct icmpv6_hdr *icmpv6, unsigned int *len);

/* Standard BSD internet checksum routine. */
unsigned short in_cksum(u16 *ptr, int nbytes);

/* Calculate the Internet checksum of some given data concatentated with the
   IPv4 pseudo-header. See RFC 1071 and TCP/IP Illustrated sections 3.2, 11.3,
   and 17.3. */
unsigned short ipv4_pseudoheader_cksum(const struct in_addr *src,
  const struct in_addr *dst, u8 proto, u16 len, const void *hstart);

/* Calculate the Internet checksum of some given data concatenated with the
   IPv6 pseudo-header. See RFC 2460 section 8.1. */
u16 ipv6_pseudoheader_cksum(const struct in6_addr *src,
  const struct in6_addr *dst, u8 nxt, u32 len, const void *hstart);

void sethdrinclude(int sd);
void set_ipoptions(int sd, void *opts, size_t optslen);
void set_ttl(int sd, int ttl);

/* Returns whether the system supports pcap_get_selectable_fd() properly */
int pcap_selectable_fd_valid();
int pcap_selectable_fd_one_to_one();

/* Call this instead of pcap_get_selectable_fd directly (or your code
   won't compile on Windows).  On systems which don't seem to support
   the pcap_get_selectable_fd() function properly, returns -1,
   otherwise simply calls pcap_selectable_fd and returns the
   results.  If you just want to test whether the function is supported,
   use pcap_selectable_fd_valid() instead. */
int my_pcap_get_selectable_fd(pcap_t *p);


/* These two function return -1 if we can't use select() on the pcap
 * device, 0 for timeout, and >0 for success. If select() fails we bail
 * out because it couldn't work with the file descriptor we got from
 * my_pcap_get_selectable_fd() */
int pcap_select(pcap_t *p, struct timeval *timeout);
int pcap_select(pcap_t *p, long usecs);

typedef enum { devt_ethernet, devt_loopback, devt_p2p, devt_other  } devtype;

#define MAX_LINK_HEADERSZ 24
struct link_header {
  int datalinktype; /* pcap_datalink(), such as DLT_EN10MB */
  int headerlen; /* 0 if header was too big or unavailaable */
  u8 header[MAX_LINK_HEADERSZ];
};

/* Relevant (to Nmap) information about an interface */
struct interface_info {
  char devname[16];
  char devfullname[16]; /* can include alias info, such as eth0:2. */
  struct sockaddr_storage addr;
  u16 netmask_bits; /* CIDR-style.  So 24 means class C (255.255.255.0)*/
  devtype device_type; /* devt_ethernet, devt_loopback, devt_p2p, devt_other */
  unsigned int ifindex; /* index (as used by if_indextoname and sin6_scope_id) */
  int device_up; /* True if the device is up (enabled) */
  int mtu; /* Interface's MTU size */
  u8 mac[6]; /* Interface MAC address if device_type is devt_ethernet */
};

struct route_nfo {
  struct interface_info ii;

/* true if the target is directly connected on the network (no routing
   required). */
  int direct_connect;

/* This is the source address that should be used by the packets.  It
   may be different than ii.addr if you are using localhost interface
   to scan the IP of another interface on the machine */
  struct sockaddr_storage srcaddr;

  /* If direct_connect is 0, this is filled in with the next hop
     required to route to the target */
  struct sockaddr_storage nexthop;
};

struct sys_route {
  struct interface_info *device;
  struct sockaddr_storage dest;
  u16 netmask_bits;
  struct sockaddr_storage gw; /* gateway - 0 if none */
  int metric;
};

struct eth_nfo {
  char srcmac[6];
  char dstmac[6];
  eth_t *ethsd; // Optional, but improves performance.  Set to NULL if unavail
  char devname[16]; // Only needed if ethsd is NULL.
};

/* A simple function that caches the eth_t from dnet for one device,
   to avoid opening, closing, and re-opening it thousands of tims.  If
   you give a different device, this function will close the first
   one.  Thus this should never be used by programs that need to deal
   with multiple devices at once.  In addition, you MUST NEVER
   eth_close() A DEVICE OBTAINED FROM THIS FUNCTION.  Instead, you can
   call eth_close_cached() to close whichever device (if any) is
   cached.  Returns NULL if it fails to open the device. */
eth_t *eth_open_cached(const char *device);

/* See the description for eth_open_cached */
void eth_close_cached();

/* Takes a protocol number like IPPROTO_TCP, IPPROTO_UDP, or
 * IPPROTO_IP and returns a ascii representation (or "unknown" if it
 * doesn't recognize the number).  Returned string is in lowercase. */
const char *proto2ascii_lowercase(u8 proto) ;

/* Same as proto2ascii() but returns a string in uppercase. */
const char *proto2ascii_uppercase(u8 proto);

/* Get an ASCII information about a tcp option which is pointed by
   optp, with a length of len. The result is stored in the result
   buffer. The result may look like "<mss 1452,sackOK,timestamp
   45848914 0,nop,wscale 7>" */
void tcppacketoptinfo(u8 *optp, int len, char *result, int bufsize);

/* Convert an IP address to the device (IE ppp0 eth0) using that
 * address.  Supplied "dev" must be able to hold at least 32 bytes.
 * Returns 0 on success or -1 in case of error. */
int ipaddr2devname( char *dev, const struct sockaddr_storage *addr );

/* Convert a network interface name (IE ppp0 eth0) to an IP address.
 * Returns 0 on success or -1 in case of error. */
int devname2ipaddr(char *dev, struct sockaddr_storage *addr);

int sockaddr_equal(const struct sockaddr_storage *a,
  const struct sockaddr_storage *b);

int sockaddr_equal_netmask(const struct sockaddr_storage *a,
  const struct sockaddr_storage *b, u16 nbits);

int sockaddr_equal_zero(const struct sockaddr_storage *s);

/* Returns an allocated array of struct interface_info representing the
   available interfaces. The number of interfaces is returned in *howmany. This
   function just does caching of results; the real work is done in
   getinterfaces_dnet() or getinterfaces_siocgifconf().
   On error, NULL is returned, howmany is set to -1 and the supplied
   error buffer "errstr", if not NULL, will contain an error message. */
struct interface_info *getinterfaces(int *howmany, char *errstr, size_t errstrlen);
/* Frees the array of cached struct interface_info used by getinterfaces. Can
   be used to force a refresh or to release memory. */
void freeinterfaces(void);

/* This struct is abused to carry either routes or interfaces, depending on the
   function it's used in. */
struct dnet_collector_route_nfo {
  struct sys_route *routes;
  int numroutes;
  int capacity; /* Capacity of routes or ifaces, depending on context */
  struct interface_info *ifaces;
  int numifaces;
};

/* Looks for an interface with the given name (iname) and address
   family type, and returns the corresponding interface_info if found.
   Will accept a match of devname or devfullname. Returns NULL if
   none found */
struct interface_info *getInterfaceByName(const char *iname, int af);

/* Parse the system routing table, converting each route into a
   sys_route entry.  Returns an array of sys_routes.  numroutes is set
   to the number of routes in the array.  The routing table is only
   read the first time this is called -- later results are cached.
   The returned route array is sorted by netmask with the most
   specific matches first.
   On error, NULL is returned, howmany is set to -1 and the supplied
   error buffer "errstr", if not NULL, will contain an error message. */
struct sys_route *getsysroutes(int *howmany, char *errstr, size_t errstrlen);

/* Tries to determine whether the supplied address corresponds to
 * localhost. (eg: the address is something like 127.x.x.x, the address
 * matches one of the local network interfaces' address, etc).
 * Returns 1 if the address is thought to be localhost and 0 otherwise */
int islocalhost(const struct sockaddr_storage *ss);

/* Determines whether the supplied address corresponds to a private,
 * non-Internet-routable address. See RFC1918 for details.
 * Also checks for link-local addresses per RFC3927.
 * Returns 1 if the address is private or 0 otherwise. */
int isipprivate(const struct sockaddr_storage *addr);

/* Takes binary data found in the IP Options field of an IPv4 packet
 * and returns a string containing an ASCII description of the options
 * found. The function returns a pointer to a static buffer that
 * subsequent calls will overwrite. On error, NULL is returned. */
char *format_ip_options(const u8* ipopt, int ipoptlen);

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
 * The function provides full support for IPv4,TCP,UDP,SCTP and ICMPv4.
 * It also provides support for standard IPv6 but not for its extension
 * headers. If an IPv6 packet contains an ICMPv6 Header, the output will
 * reflect this but no parsing of ICMPv6 contents will be performed.
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
#define LOW_DETAIL     1
#define MEDIUM_DETAIL  2
#define HIGH_DETAIL    3
const char *ippackethdrinfo(const u8 *packet, u32 len, int detail);


/* Takes an IPv4 destination address (dst) and tries to determine the
 * source address and interface necessary to route to this address.
 * If no route is found, 0 is returned and "rnfo" is undefined.  If
 * a route is found, 1 is returned and "rnfo" is filled in with all
 * of the routing details. If the source address needs to be spoofed,
 * it should be passed through "spoofss" (otherwise NULL should be
 * specified), along with a suitable network device (parameter "device").
 * Even if spoofss is NULL, if user specified a network device with -e,
 * it should still be passed. Note that it's OK to pass either NULL or
 * an empty string as the "device", as long as spoofss==NULL. */
int route_dst(const struct sockaddr_storage *dst, struct route_nfo *rnfo,
              const char *device, const struct sockaddr_storage *spoofss);

/* Send an IP packet over a raw socket. */
int send_ip_packet_sd(int sd, const struct sockaddr_in *dst, const u8 *packet, unsigned int packetlen);

/* Send an IP packet over an ethernet handle. */
int send_ip_packet_eth(const struct eth_nfo *eth, const u8 *packet, unsigned int packetlen);

/* Sends the supplied pre-built IPv4 packet. The packet is sent through
 * the raw socket "sd" if "eth" is NULL. Otherwise, it gets sent at raw
 * ethernet level. */
int send_ip_packet_eth_or_sd(int sd, const struct eth_nfo *eth,
  const struct sockaddr_in *dst, const u8 *packet, unsigned int packetlen);

/* Sends an IPv4 packet. */
int send_ipv6_packet_eth_or_sd(int sd, const struct eth_nfo *eth,
  const struct sockaddr_in6 *dst, const u8 *packet, unsigned int packetlen);

/* Create and send all fragments of a pre-built IPv4 packet.
 * Minimal MTU for IPv4 is 68 and maximal IPv4 header size is 60
 * which gives us a right to cut TCP header after 8th byte */
int send_frag_ip_packet(int sd, const struct eth_nfo *eth,
  const struct sockaddr_in *dst,
  const u8 *packet, unsigned int packetlen, u32 mtu);

/* Wrapper for system function sendto(), which retries a few times when
 * the call fails. It also prints informational messages about the
 * errors encountered. It returns the number of bytes sent or -1 in
 * case of error. */
int Sendto(const char *functionname, int sd, const unsigned char *packet,
           int len, unsigned int flags, struct sockaddr *to, int tolen);

/* This function is  used to obtain a packet capture handle to look at
 * packets on the network. It is actually a wrapper for libpcap's
 * pcap_open_live() that takes care of compatibility issues and error
 * checking.  Prints an error and fatal()s if the call fails, so a
 * valid pcap_t will always be returned. */
pcap_t *my_pcap_open_live(const char *device, int snaplen, int promisc, int to_ms);

/* Set a pcap filter */
void set_pcap_filter(const char *device, pcap_t *pd, const char *bpf, ...);

/* Issues an ARP request for the MAC of targetss (which will be placed
   in targetmac if obtained) from the source IP (srcip) and source mac
   (srcmac) given.  "The request is ussued using device dev to the
   broadcast MAC address.  The transmission is attempted up to 3
   times.  If none of these elicit a response, false will be returned.
   If the mac is determined, true is returned. The last parameter is
   a pointer to a callback function that can be used for packet traceing.
   This is intended to be used by Nmap only. Any other calling this
   should pass NULL instead. */
bool doArp(const char *dev, const u8 *srcmac,
                  const struct sockaddr_storage *srcip,
                  const struct sockaddr_storage *targetip,
                  u8 *targetmac,
                  void (*traceArp_callback)(int, const u8 *, u32 , struct timeval *));


/* Issues an Neighbor Solicitation for the MAC of targetss (which will be placed
   in targetmac if obtained) from the source IP (srcip) and source mac
   (srcmac) given.  "The request is ussued using device dev to the
   multicast MAC address.  The transmission is attempted up to 3
   times.  If none of these elicit a response, false will be returned.
   If the mac is determined, true is returned. The last parameter is
   a pointer to a callback function that can be used for packet tracing.
   This is intended to be used by Nmap only. Any other calling this
   should pass NULL instead. */
bool doND(const char *dev, const u8 *srcmac,
                  const struct sockaddr_storage *srcip,
                   const struct sockaddr_storage *targetip,
                   u8 *targetmac,
                   void (*traceArp_callback)(int, const u8 *, u32 , struct timeval *)
                    ) ;

/* Attempts to read one IPv4/Ethernet ARP reply packet from the pcap
   descriptor pd.  If it receives one, fills in sendermac (must pass
   in 6 bytes), senderIP, and rcvdtime (can be NULL if you don't care)
   and returns 1.  If it times out and reads no arp requests, returns
   0.  to_usec is the timeout period in microseconds.  Use 0 to avoid
   blocking to the extent possible.  Returns -1 or exits if there is
   an error.  The last parameter is a pointer to a callback function
   that can be used for packet tracing. This is intended to be used
   by Nmap only. Any other calling this should pass NULL instead. */
int read_arp_reply_pcap(pcap_t *pd, u8 *sendermac,
                        struct in_addr *senderIP, long to_usec,
                        struct timeval *rcvdtime,
                        void (*traceArp_callback)(int, const u8 *, u32 , struct timeval *));
int read_ns_reply_pcap(pcap_t *pd, u8 *sendermac,
                        struct sockaddr_in6 *senderIP, long to_usec,
                        struct timeval *rcvdtime, bool *has_mac,
                        void (*traceArp_callback)(int, const u8 *, u32 , struct timeval *));

/* Attempts to read one IP packet from the pcap descriptor pd. Input parameters are pd,
   to_usec, and accept_callback. If a received frame passes accept_callback,
   then the output parameters p, head, rcvdtime, datalink, and offset are filled
   in, and the function returns 1. If no frame passes before the timeout, then
   the function returns 0 and the output parameters are undefined. */
int read_reply_pcap(pcap_t *pd, long to_usec,
  bool (*accept_callback)(const unsigned char *, const struct pcap_pkthdr *, int, size_t),
  const unsigned char **p, struct pcap_pkthdr **head, struct timeval *rcvdtime,
  int *datalink, size_t *offset);

/* Read a single host specification from a file, as for -iL and --excludefile.
   It returns the length of the string read; an overflow is indicated when the
   return value is >= n. Returns 0 if there was no specification to be read. The
   buffer is always null-terminated. */
size_t read_host_from_file(FILE *fp, char *buf, size_t n);

/* Return next target host specification from the supplied stream.
 * if parameter "random" is set to true, then the function will
 * return a random, non-reserved, IP address in decimal-dot notation */
const char *grab_next_host_spec(FILE *inputfd, bool random, int argc, const char **fakeargv);

#ifdef WIN32
/* Convert a dnet interface name into the long pcap style.  This also caches the
   data to speed things up.  Fills out pcapdev (up to pcapdevlen) and returns
   true if it finds anything. Otherwise returns false.  This is only necessary
   on Windows. */
int DnetName2PcapName(const char *dnetdev, char *pcapdev, int pcapdevlen);
#endif

/** Tries to increase the open file descriptor limit for this process.
  * @param "desired" is the number of desired max open descriptors. Pass a
  * negative value to set the maximum allowed.
  * @return the number of max open descriptors that could be set, or 0 in case
  * of failure.
  * @warning if "desired" is less than the current limit, no action is
  * performed. This function may only be used to increase the limit, not to
  * decrease it. */
int set_max_open_descriptors(int desired_max);

/** Returns the open file descriptor limit for this process.
  * @return the number of max open descriptors or 0 in case of failure. */
int get_max_open_descriptors();

/* Maximize the open file descriptor limit for this process go up to the
   max allowed  */
int max_sd();

#endif /* _NETUTIL_H_ */
