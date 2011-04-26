
/***************************************************************************
 * netutil.h -- The main include file exposing the external API for        *
 * libnetutil, a library that provides network-related functions or        *
 * classes that make it easier to handle things like network interfaces,   *
 * routing tables, raw packet manipulation, etc. The lib was originally    *
 * written for use in the Nmap Security Scanner ( http://nmap.org ).       *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-db or nmap-service-probes.                                    *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                *
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is meant to clarify our *
 * interpretation of derived works with some common examples.  Our         *
 * interpretation applies only to Nmap--we don't speak for other people's  *
 * GPL works.                                                              *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two. You must obey the GNU GPL in all *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to nmap-dev@insecure.org for possible incorporation into the main       *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because the *
 * inability to relicense code has caused devastating problems for other   *
 * Free Software projects (such as KDE and NASM).  We also occasionally    *
 * relicense the code to third parties as discussed above.  If you wish to *
 * specify special license conditions of your contributions, just say so   *
 * when you send them.                                                     *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
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

enum { OP_FAILURE = -1, OP_SUCCESS = 0 };


/* For systems without SCTP in netinet/in.h, such as MacOS X or Win */
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

int netutil_fatal(const char *str, ...)
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

/* Tries to resolve the given name (or literal IP) into a sockaddr structure.
   - Parameter "hostname" is the name to be resolved.
   - Parameter "port" sets the port in each returned address structure
     (you can safely pass 0 for the port if you don't care)
   - Parameter "nodns": If set, it means that the supplied hostname is actually a
     numeric IP address. The flag prevents any type of name resolution service
     from being called. In 99% of the cases this should be 0.
   Returns 1 on success or 0 if hostname could not be resolved. */
int resolve(const char *hostname, u16 port, int nodns, struct sockaddr_storage *ss, size_t *sslen, int af);

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
 * Address entries. Function arp_cache_get() looks for the IPv4 address
 * in ss and fills in the 'mac' parameter and returns true if it is
 * found.  Otherwise (not found), the function returns false.
 * Function arp_cache_set() adds an entry with the given ip (ss) and
 * mac address.  An existing entry for the IP ss will be overwritten
 * with the new MAC address.  arp_cache_set() always returns true. */
int arp_cache_get(struct sockaddr_storage *ss, u8 *mac);
int arp_cache_set(struct sockaddr_storage *ss, u8 *mac);

/* Standard BSD internet checksum routine. */
unsigned short in_cksum(u16 *ptr, int nbytes);

/* Calculate the Internet checksum of some given data concatentated with the
   IPv4 pseudo-header. See RFC 1071 and TCP/IP Illustrated sections 3.2, 11.3,
   and 17.3. */
unsigned short ipv4_pseudoheader_cksum(const struct in_addr *src,
  const struct in_addr *dst, u8 proto, u16 len, const void *hstart);

void sethdrinclude(int sd);
void set_ipoptions(int sd, void *opts, size_t optslen);
void set_ttl(int sd, int ttl);

/* Returns whether the system supports pcap_get_selectable_fd() properly */
int pcap_selectable_fd_valid();

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
  u32 dest;
  u32 netmask;
  struct in_addr gw; /* gateway - 0 if none */
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
int ipaddr2devname( char *dev, const struct in_addr *addr );

/* Convert a network interface name (IE ppp0 eth0) to an IPv4 address.
 * Returns 0 on success or -1 in case of error. */
int devname2ipaddr(char *dev, struct in_addr *addr);

/* Returns an allocated array of struct interface_info representing the
   available interfaces. The number of interfaces is returned in *howmany. This
   function just does caching of results; the real work is done in
   getinterfaces_dnet() or getinterfaces_siocgifconf().
   On error, NULL is returned, howmany is set to -1 and the supplied
   error buffer "errstr", if not NULL, will contain an error message. */
struct interface_info *getinterfaces(int *howmany, char *errstr, size_t errstrlen);

/* This struct is abused to carry either routes or interfaces, depending on the
   function it's used in. */
struct dnet_collector_route_nfo {
  struct sys_route *routes;
  int numroutes;
  int capacity; /* Capacity of routes or ifaces, depending on context */
  struct interface_info *ifaces;
  int numifaces;
};

/* Looks for an interface with the given name (iname), and returns the
   corresponding interface_info if found.  Will accept a match of
   devname or devfullname.  Returns NULL if none found */
struct interface_info *getInterfaceByName(const char *iname);

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
int islocalhost(const struct in_addr *const addr);

/* Determines whether the supplied address corresponds to a private,
 * non-Internet-routable address. See RFC1918 for details.
 * Returns 1 if the address is private or 0 otherwise. */
int isipprivate(const struct in_addr *const addr);

/* Takes binary data found in the IP Options field of an IPv4 packet
 * and returns a string containing an ASCII description of the options
 * found. The function returns a pointer to a static buffer that
 * subsequent calls will overwrite. On error, NULL is returned. */
char *format_ip_options(u8* ipopt, int ipoptlen);

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
int route_dst(const struct sockaddr_storage * const dst, struct route_nfo *rnfo,
              char *device, struct sockaddr_storage *spoofss);

/* Send an IP packet over a raw socket. */
int send_ip_packet_sd(int sd, u8 *packet, unsigned int packetlen);

/* Send an IP packet over an ethernet handle. */
int send_ip_packet_eth(struct eth_nfo *eth, u8 *packet, unsigned int packetlen);

/* Sends the supplied pre-built IPv4 packet. The packet is sent through
 * the raw socket "sd" if "eth" is NULL. Otherwise, it gets sent at raw
 * ethernet level. */
int send_ip_packet_eth_or_sd(int sd, struct eth_nfo *eth, u8 *packet, unsigned int packetlen);

/* Create and send all fragments of a pre-built IPv4 packet.
 * Minimal MTU for IPv4 is 68 and maximal IPv4 header size is 60
 * which gives us a right to cut TCP header after 8th byte */
int send_frag_ip_packet(int sd, struct eth_nfo *eth, u8 *packet,
                        unsigned int packetlen, u32 mtu);

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

/* Read a single host specification from a file, as for -iL and --excludefile.
   It returns the length of the string read; an overflow is indicated when the
   return value is >= n. Returns 0 if there was no specification to be read. The
   buffer is always null-terminated. */
size_t read_host_from_file(FILE *fp, char *buf, size_t n);

/* Return next target host specification from the supplied stream.
 * if parameter "random" is set to true, then the function will
 * return a random, non-reserved, IP address in decimal-dot notation */
char *grab_next_host_spec(FILE *inputfd, bool random, int argc, char **fakeargv);

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
