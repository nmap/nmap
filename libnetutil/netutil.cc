
/***************************************************************************
 * netutil.cc                                                              *
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

#if HAVE_CONFIG_H
#include "../nmap_config.h"
#endif

#include "nbase.h"

#ifdef WIN32
#include "mswin32/winclude.h"
#include "pcap-int.h"
#else
#include <sys/ioctl.h>
#endif

#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>  /* SIOCGIFCONF for Solaris */
#endif
#include <net/if_arp.h>

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifndef NETINET_IN_SYSTM_H  /* This guarding is needed for at least some versions of OpenBSD */
#include <netinet/in_systm.h>
#define NETINET_IN_SYSTM_H
#endif

#if HAVE_NET_IF_H
#ifndef NET_IF_H /* This guarding is needed for at least some versions of OpenBSD */
#include <net/if.h>
#define NET_IF_H
#endif
#endif
#ifndef NETINET_IP_H  /* This guarding is needed for at least some versions of OpenBSD */
#include <netinet/ip.h> 
#define NETINET_IP_H
#endif

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include "netutil.h"

#define NBASE_MAX_ERR_STR_LEN 1024  /* Max length of an error message */

/** Print fatal error messages to stderr and then exits. A newline
    character is printed automatically after the supplied text.
 * @warning This function does not return because it calls exit() */
int netutil_fatal(const char *str, ...){
 va_list  list;
 char errstr[NBASE_MAX_ERR_STR_LEN];
 memset(errstr,0, NBASE_MAX_ERR_STR_LEN);

  va_start(list, str);

  fflush(stdout);

  /* Print error msg to strerr */
  vfprintf(stderr, str, list);
  fprintf(stderr,"\n");
  va_end(list);

  exit(EXIT_FAILURE);

  return 0;

} /* End of fatal() */

/** Print error messages to stderr and then return. A newline
    character is printed automatically after the supplied text.*/
int netutil_error(const char *str, ...){
 va_list  list;
 char errstr[NBASE_MAX_ERR_STR_LEN];
 memset(errstr,0, NBASE_MAX_ERR_STR_LEN);

  va_start(list, str);

  fflush(stdout);

  /* Print error msg to strerr */
  vfprintf(stderr, str, list);
  fprintf(stderr,"\n");
  va_end(list);

  return 0;

} /* End of error() */

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
int parse_ip_options(const char *txt, u8 *data, int datalen, int* firsthopoff, int* lasthopoff, char *errstr, size_t errstrlen){
  enum{
    NONE  = 0,
    SLASH = 1,
    MUL   = 2,
    RR	  = 3,
    TIME  = 4,
  } s = NONE;
  char *n, lc;
  const char *c = txt;
  u8 *d = data;
  int i,j;
  int base = 10;
  u8 *dataend = &data[datalen];
  u8 *len = NULL;
  char buf[32];
  memset(data, 0, datalen);
  int sourcerouting = 0;


  for(;*c;c++){
    switch(s){
    case SLASH:
      // parse \x00 string
      if(*c == 'x'){// just ignore this char
      	base = 16;
        break;
      }
      if(isxdigit(*c)){
        *d++ = strtol(c, &n, base);
        c=n-1;
      }else{
          if(errstr) Snprintf(errstr, errstrlen, "not a digit after '\\'");
          return OP_FAILURE;
      }
      s = NONE;
      break;
    case MUL:
      if(d==data){
        if(errstr) Snprintf(errstr, errstrlen, "nothing before '*' char");
          return OP_FAILURE;
      }
      i = strtol(c, &n, 10);
      if(i<2){
        if(errstr) Snprintf(errstr, errstrlen, "bad number after '*'");
        return OP_FAILURE;
      }
      c = n-1;		// move current txt pointer
      lc = *(d-1);	// last char, we'll copy this
      for(j=1; j<i; j++){
        *d++ = lc;
        if(d == dataend) // check for overflow
          goto after;
      }
      s = NONE;
      break;
    case RR:
      if(*c==' ' || *c==',')
        break;
      n = buf;
      while((*c=='.' || (*c>='0' && *c<='9')) && n-buf <= ((int)sizeof(buf)-1))
      	 *n++ = *c++;
      *n = '\0'; c--;
      if(d+4>=dataend){
        if(errstr) Snprintf(errstr, errstrlen, "Buffer too small. Or input data too big :)");
        return OP_FAILURE;
      }
      i = inet_pton(AF_INET, buf, d);
      if(i<1){
        if(errstr) Snprintf(errstr, errstrlen, "Not a valid ipv4 address '%s'",buf);
        return OP_FAILURE;
      }
      // remember offset of first hop
      if(sourcerouting && !*firsthopoff)
        *firsthopoff = d - data;
      d+=4;
      if(*len<37)
        *len += 4;
      break;
    case TIME:
      if(errstr) Snprintf(errstr, errstrlen, "No more arguments allowed!");
      return OP_FAILURE;
    default:
      switch(*c){
      case '\\':s = SLASH;base=10;break;
      case '*':s = MUL;break;
      case 'R':
      case 'S':
      case 'L':
        if(d != data){
          if(errstr) Snprintf(errstr, errstrlen, "This option can't be used in that way");
          return OP_FAILURE;
        }
        *d++ = '\x01';//NOP
        switch(*c){
        case 'R':*d++ = 7;break;
        case 'S':*d++ = 137; sourcerouting=1; break;
        case 'L':*d++ = 131; sourcerouting=1; break;
        }
	len = d;
        *d++ = (*c=='R')? 39 : 3; // length: 3+4*9 bytes
        *d++ = 4; //pointer
        s = RR;
        break;
      case 'T':
      case 'U':
        if(d != data){
          if(errstr) Snprintf(errstr, errstrlen, "This option can't be used in that way");
          return OP_FAILURE;
        }
	*d++ = 68;	// option type
	len = d;
        *d++ = (*c=='U') ? 36 : 40;   // length: 3+4*9 bytes or 4+4*9 bytes
        *d++ = 5; // pointer
        *d++ = (*c=='U') ? 1 : 0; // flag: address and Time fields
        s = TIME;
        break;
      default://*d++ = *c;
      	if(errstr) Snprintf(errstr, errstrlen, "Bad character in ip option '%c'",*c);
          return OP_FAILURE;
      }
    }
    if(d == dataend)
      break;
    assert(d<dataend);
  }
  if(sourcerouting){
    if(*len<37){
      *len+=4;
      *lasthopoff = d - data;
      *d++ = 0;*d++ = 0;*d++ = 0;*d++ = 0;
    }else{
      if(errstr) Snprintf(errstr, errstrlen, "When using source routing you must leave at least one slot for target's ip.");
      return OP_FAILURE;    
    }
  }
  if(s == RR)
    return(*len+1); // because we inject NOP before
  if(s == TIME)
    return(*len);
after:
  return(d - data);
}

/* Tries to resolve the given name (or literal IP) into a sockaddr structure.
   - Parameter "hostname" is the name to be resolved.
   - Parameter "port" sets the port in each returned address structure
     (you can safely pass 0 for the port if you don't care)
   - Parameter "nodns": If set, it means that the supplied hostname is actually a
     numeric IP address. The flag prevents any type of name resolution service
     from being called. In 99% of the cases this should be 0.
   Returns 1 on success or 0 if hostname could not be resolved. */
int resolve(const char *hostname, u16 port, int nodns, struct sockaddr_storage *ss, size_t *sslen, int af){
  struct addrinfo hints;
  struct addrinfo *result;
  char portbuf[16];
  size_t rc=0;

  assert(hostname);
  assert(ss);
  assert(sslen);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = af;
  hints.ai_socktype = SOCK_DGRAM;
  if (nodns)
     hints.ai_flags |= AI_NUMERICHOST;

  /* Make the port number a string to give to getaddrinfo. */
  rc = Snprintf(portbuf, sizeof(portbuf), "%hu", port);
  assert(rc >= 0 && rc < sizeof(portbuf));

  rc = getaddrinfo(hostname, portbuf, &hints, &result);
  if (rc != 0 || result == NULL)
      return 0;
  assert(result->ai_addrlen > 0 && result->ai_addrlen <= (int) sizeof(struct sockaddr_storage));
  *sslen = result->ai_addrlen;
  memcpy(ss, result->ai_addr, *sslen);
  freeaddrinfo(result);
  return 1;
}

/*
 * Returns 1 if this is a reserved IP address, where "reserved" means
 * either a private address, non-routable address, or even a non-reserved
 * but unassigned address which has an extremely high probability of being
 * black-holed.
 *
 * We try to optimize speed when ordering the tests. This optimization
 * assumes that all byte values are equally likely in the input.
 *
 * Check
 * <http://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.txt>
 * for the most recent assigments and
 * <http://www.cymru.com/Documents/bogon-bn-nonagg.txt> for bogon
 * netblocks.
 */
int ip_is_reserved(struct in_addr *ip)
{
  char *ipc = (char *) &(ip->s_addr);
  unsigned char i1 = ipc[0], i2 = ipc[1], i3 = ipc[2]; /* i4 not currently used - , i4 = ipc[3]; */

  /* do all the /7's and /8's with a big switch statement, hopefully the
   * compiler will be able to optimize this a little better using a jump table
   * or what have you
   */
  switch (i1)
    {
    case 0:         /* 000/8 is IANA reserved       */
    case 6:         /* USA Army ISC                 */
    case 7:         /* used for BGP protocol        */
    case 10:        /* the infamous 10.0.0.0/8      */
    case 55:        /* misc. U.S.A. Armed forces    */
    case 127:       /* 127/8 is reserved for loopback */
      return 1;
    default:
      break;
    }

  /* 172.16.0.0/12 is reserved for private nets by RFC1819 */
  if (i1 == 172 && i2 >= 16 && i2 <= 31)
    return 1;

  /* 192.0.2.0/24 is reserved for documentation and examples (RFC5737) */
  /* 192.88.99.0/24 is used as 6to4 Relay anycast prefix by RFC3068 */
  /* 192.168.0.0/16 is reserved for private nets by RFC1819 */
  if (i1 == 192) {
    if (i2 == 0 && i3 == 2)
      return 1;
    if (i2 == 88 && i3 == 99)
      return 1;
    if (i2 == 168)
      return 1;
  }

  /* 198.18.0.0/15 is used for benchmark tests by RFC2544 */
  /* 198.51.100.0/24 is reserved for documentation (RFC5737) */
  if (i1 == 198) {
    if (i2 == 18 || i2 == 19)
      return 1;
    if (i2 == 51 && i3 == 100)
      return 1;
  }

  /* 169.254.0.0/16 is reserved for DHCP clients seeking addresses */
  if (i1 == 169 && i2 == 254)
    return 1;
 
  /* 203.0.113.0/24 is reserved for documentation (RFC5737) */
  if (i1 == 203 && i2 == 0 && i3 == 113)
    return 1;

  /* 224-239/8 is all multicast stuff */
  /* 240-255/8 is IANA reserved */
  if (i1 >= 224)
    return 1;

  return 0;
}

/* A trivial functon that maintains a cache of IP to MAC Address
   entries.  If the command is ARPCACHE_GET, this func looks for the
   IPv4 address in ss and fills in the 'mac' parameter and returns
   true if it is found.  Otherwise (not found), the function returns
   false.  If the command is ARPCACHE_SET, the function adds an entry
   with the given ip (ss) and mac address.  An existing entry for the
   IP ss will be overwritten with the new MAC address.  true is always
   returned for the set command.
   WARNING: The caller must ensure that the supplied "ss" is of family
   AF_INET. Otherwise the function will return 0 and there would be
   no way for the caller to tell tell the difference between an error
   or a cache miss. */
#define ARPCACHE_GET 1
#define ARPCACHE_SET 2
static int do_arp_cache(int command, struct sockaddr_storage *ss, u8 *mac) {
  struct sockaddr_in *sin = (struct sockaddr_in *) ss;
  struct ArpCache {
    u32 ip; /* Network byte order */
    u8 mac[6];
  };
  static struct ArpCache *Cache = NULL;
  static int ArpCapacity = 0;
  static int ArpCacheSz = 0;
  int i;

  if (sin->sin_family != AF_INET)
    return 0;

  if (command == ARPCACHE_GET) {
    for (i = 0; i < ArpCacheSz; i++) {
      if (Cache[i].ip == sin->sin_addr.s_addr) {
        memcpy(mac, Cache[i].mac, 6);
        return 1;
      }
    }
    return 0;
  }
  assert(command == ARPCACHE_SET);
  if (ArpCacheSz == ArpCapacity) {
    if (ArpCapacity == 0)
      ArpCapacity = 32;
    else
      ArpCapacity <<= 2;
    Cache = (struct ArpCache *) safe_realloc(Cache, ArpCapacity * sizeof(struct ArpCache));
  }

  /* Ensure that it isn't already there ... */
  for (i = 0; i < ArpCacheSz; i++) {
    if (Cache[i].ip == sin->sin_addr.s_addr) {
      memcpy(Cache[i].mac, mac, 6);
      return 1;
    }
  }

  /* Add it to the end of the list */
  Cache[i].ip = sin->sin_addr.s_addr;
  memcpy(Cache[i].mac, mac, 6);
  ArpCacheSz++;
  return 1;
}

/* A couple of trivial functions that maintain a cache of IP to MAC
 * Address entries. Function arp_cache_get() looks for the IPv4 address
 * in ss and fills in the 'mac' parameter and returns true if it is
 * found.  Otherwise (not found), the function returns false.
 * Function arp_cache_set() adds an entry with the given ip (ss) and
 * mac address.  An existing entry for the IP ss will be overwritten
 * with the new MAC address.  arp_cache_set() always returns true.
 * WARNING: The caller must ensure that the supplied "ss" is of family
 * AF_INET. Otherwise the function will return 0 and there would be
 * no way for the caller to tell tell the difference between an error
 * or a cache miss.*/
int arp_cache_get(struct sockaddr_storage *ss, u8 *mac){
    return do_arp_cache(ARPCACHE_GET, ss, mac);
}
int arp_cache_set(struct sockaddr_storage *ss, u8 *mac){
    return do_arp_cache(ARPCACHE_SET, ss, mac);
}

/* Standard BSD internet checksum routine. Uses libdnet helper functions. */
unsigned short in_cksum(u16 *ptr,int nbytes) {
  int sum;

   sum = ip_cksum_add(ptr, nbytes, 0);

  return ip_cksum_carry(sum);

  return 0;
}


/* Calculate the Internet checksum of some given data concatentated with the
   IPv4 pseudo-header. See RFC 1071 and TCP/IP Illustrated sections 3.2, 11.3,
   and 17.3. */
unsigned short ipv4_pseudoheader_cksum(const struct in_addr *src,
  const struct in_addr *dst, u8 proto, u16 len, const void *hstart) {
  struct pseudo {
    struct in_addr src;
    struct in_addr dst;
    u8 zero;
    u8 proto;
    u16 length;
  } hdr;
  int sum;

  hdr.src = *src;
  hdr.dst = *dst;
  hdr.zero = 0;
  hdr.proto = proto;
  hdr.length = htons(len);

  /* Get the ones'-complement sum of the pseudo-header. */
  sum = ip_cksum_add(&hdr, sizeof(hdr), 0);
  /* Add it to the sum of the packet. */
  sum = ip_cksum_add(hstart, len, sum);

  /* Fold in the carry, take the complement, and return. */
  return ip_cksum_carry(sum);
}

void sethdrinclude(int sd) {
#ifdef IP_HDRINCL
  int one = 1;
  setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (const char *) &one, sizeof(one));
#endif
}

void set_ipoptions(int sd, void *opts, size_t optslen) {
#ifdef IP_OPTIONS
  if (sd == -1)
    return;

  setsockopt(sd, IPPROTO_IP, IP_OPTIONS, (const char *) opts, optslen);
#endif
}

void set_ttl(int sd, int ttl) {
#ifdef IP_TTL
  if (sd == -1)
    return;

  setsockopt(sd, IPPROTO_IP, IP_TTL, (const char *) &ttl, sizeof ttl);
#endif
}

/* Returns whether the system supports pcap_get_selectable_fd() properly */
int pcap_selectable_fd_valid() {
#if defined(WIN32) || defined(MACOSX) || (defined(FREEBSD) && (__FreeBSD_version < 500000))
  return 0;
#else
  return 1;
#endif
}

/* Call this instead of pcap_get_selectable_fd directly (or your code
   won't compile on Windows).  On systems which don't seem to support
   the pcap_get_selectable_fd() function properly, returns -1,
   otherwise simply calls pcap_selectable_fd and returns the
   results.  If you just want to test whether the function is supported,
   use pcap_selectable_fd_valid() instead. */
int my_pcap_get_selectable_fd(pcap_t *p) {
#if defined(WIN32) || defined(MACOSX) || (defined(FREEBSD) && (__FreeBSD_version < 500000))
  return -1;
#else
  assert(pcap_selectable_fd_valid());
  return pcap_get_selectable_fd(p);
#endif
}


/* returns -1 if we can't use select() on the pcap device, 0 for timeout, and
 * >0 for success. If select() fails we bail out because it couldn't work with
 * the file descriptor we got from my_pcap_get_selectable_fd()
 */
int pcap_select(pcap_t *p, struct timeval *timeout) {
  int fd, ret;
  fd_set rfds;

  if ((fd = my_pcap_get_selectable_fd(p)) == -1)
    return -1;

  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);

  do {
    errno = 0;
    ret = select(fd + 1, &rfds, NULL, NULL, timeout);
    if (ret == -1) {
      if (errno == EINTR)
        netutil_error("%s: %s", __func__, strerror(errno));
      else
        netutil_fatal("Your system does not support select()ing on pcap devices (%s). PLEASE REPORT THIS ALONG WITH DETAILED SYSTEM INFORMATION TO THE nmap-dev MAILING LIST!", strerror(errno));
    }
  } while (ret == -1);

  return ret;
}

int pcap_select(pcap_t *p, long usecs) {
  struct timeval tv;

  tv.tv_sec = usecs / 1000000;
  tv.tv_usec = usecs % 1000000;

  return pcap_select(p, &tv);
}


/* These two are for eth_open_cached() and eth_close_cached() */
static char etht_cache_device_name[64];
static eth_t *etht_cache_device = NULL;

/* A simple function that caches the eth_t from dnet for one device,
   to avoid opening, closing, and re-opening it thousands of tims.  If
   you give a different device, this function will close the first
   one.  Thus this should never be used by programs that need to deal
   with multiple devices at once.  In addition, you MUST NEVER
   eth_close() A DEVICE OBTAINED FROM THIS FUNCTION.  Instead, you can
   call eth_close_cached() to close whichever device (if any) is
   cached.  Returns NULL if it fails to open the device. */
eth_t *eth_open_cached(const char *device) {
  if (!device)
    netutil_fatal("%s() called with NULL device name!", __func__);
  if (!*device)
    netutil_fatal("%s() called with empty device name!", __func__);

  if (strcmp(device, etht_cache_device_name) == 0) {
    /* Yay, we have it cached. */
    return etht_cache_device;
  }

  if (*etht_cache_device_name) {
    eth_close(etht_cache_device);
    etht_cache_device_name[0] = '\0';
    etht_cache_device = NULL;
  }

  etht_cache_device = eth_open(device);
  if (etht_cache_device)
    Strncpy(etht_cache_device_name, device,
            sizeof(etht_cache_device_name));

  return etht_cache_device;
}

/* See the description for eth_open_cached */
void eth_close_cached() {
  if (etht_cache_device) {
    eth_close(etht_cache_device);
    etht_cache_device = NULL;
    etht_cache_device_name[0] = '\0';
  }
  return;
}

/* Takes a protocol number like IPPROTO_TCP, IPPROTO_UDP, IPPROTO_IP,
 * etc, and returns an ASCII representation (or the string "unknown" if
 * it doesn't recognize the number). If uppercase is non zero, the
 * returned value will be in uppercase letters, otherwise it'll be
 * in lowercase */
const char *proto2ascii_case(u8 proto, int uppercase) {
  switch (proto) {

  case IPPROTO_TCP:
    return uppercase ? "TCP" : "tcp";
    break;
  case IPPROTO_UDP:
    return uppercase ? "UDP" : "udp";
    break;
  case IPPROTO_SCTP:
    return uppercase ? "SCTP" : "sctp";
    break;
  case IPPROTO_IP:
    return uppercase ? "IP" : "ip";
    break;
#ifdef IPPROTO_ICMP
  case IPPROTO_ICMP:
    return uppercase ? "ICMP" : "icmp";
    break;
#endif
#ifdef IPPROTO_IPV6
  case IPPROTO_IPV6:
    return uppercase ? "IPv6" : "ipv6";
    break;
#endif
#ifdef IPPROTO_ICMPV6
  case IPPROTO_ICMPV6:
    return uppercase ? "ICMPv6" : "icmpv6";
    break;
#endif
#ifdef IPPROTO_GRE
  case IPPROTO_GRE: // Generic Routing Encapsulation
    return uppercase ? "GRE" : "gre";
    break;
#endif
#ifdef IPPROTO_ESP
  case IPPROTO_ESP: // Encapsulating Security Payload (IPSec)
    return uppercase ? "IPSec/ESP" : "ipsec/esp";
    break;
#endif
#ifdef IPPROTO_AH
  case IPPROTO_AH: // Authentication Header (IPSec)
    return uppercase ? "IPSec/AH" : "ipsec/ah";
    break;
#endif
  default:
    return uppercase ? "UNKNOWN" : "unknown";
  }

  return NULL; // Unreached
}

const char *proto2ascii_lowercase(u8 proto) {
    return proto2ascii_case(proto, 0);
}
const char *proto2ascii_uppercase(u8 proto) {
    return proto2ascii_case(proto, 1);
}

/* Get an ASCII information about a tcp option which is pointed by
   optp, with a length of len. The result is stored in the result
   buffer. The result may look like "<mss 1452,sackOK,timestamp
   45848914 0,nop,wscale 7>" */
void tcppacketoptinfo(u8 *optp, int len, char *result, int bufsize) {
  assert(optp);
  assert(result);
  char *p, ch;
  u8 *q;
  int opcode;
  u16 tmpshort;
  u32 tmpword1, tmpword2;
  unsigned int i=0;

  p = result;
  *p = '\0';
  q = optp;
  ch = '<';

  while (len > 0 && bufsize > 2) {
    Snprintf(p, bufsize, "%c", ch);
    bufsize--;
    p++;
    opcode = *q++;
    if (!opcode) { /* End of List */

      Snprintf(p, bufsize, "eol");
      bufsize -= strlen(p);
      p += strlen(p);

      len--;

    } else if (opcode == 1) { /* No Op */
      Snprintf(p, bufsize, "nop");
      bufsize -= strlen(p);
      p += strlen(p);

      len--;
    } else if (opcode == 2) { /* MSS */
      if (len < 4)
        break; /* MSS has 4 bytes */

      q++;
      memcpy(&tmpshort, q, 2);

      Snprintf(p, bufsize, "mss %u", ntohs(tmpshort));
      bufsize -= strlen(p);
      p += strlen(p);

      q += 2;
      len -= 4;
    } else if (opcode == 3) { /* Window Scale */
      if (len < 3)
        break; /* Window Scale option has 3 bytes */

      q++;

      Snprintf(p, bufsize, "wscale %u", *q);
      bufsize -= strlen(p);
      p += strlen(p);

      q++;
      len -= 3;
    } else if (opcode == 4) { /* SACK permitted */
      if (len < 2)
        break; /* SACK permitted option has 2 bytes */

      Snprintf(p, bufsize, "sackOK");
      bufsize -= strlen(p);
      p += strlen(p);

      q++;
      len -= 2;
    } else if (opcode == 5) { /* SACK */
      unsigned sackoptlen = *q;
      if ((unsigned) len < sackoptlen)
        break;

      /* This would break parsing, so it's best to just give up */
      if (sackoptlen < 2)
        break;

      q++;

      if ((sackoptlen - 2) == 0 || ((sackoptlen - 2) % 8 != 0)) {
        Snprintf(p, bufsize, "malformed sack");
        bufsize -= strlen(p);
        p += strlen(p);
      } else {
        Snprintf(p, bufsize, "sack %d ", (sackoptlen - 2) / 8);
        bufsize -= strlen(p);
        p += strlen(p);
        for (i = 0; i < sackoptlen - 2; i += 8) {
          memcpy(&tmpword1, q + i, 4);
          memcpy(&tmpword2, q + i + 4, 4);
          Snprintf(p, bufsize, "{%u:%u}", tmpword1, tmpword2);
          bufsize -= strlen(p);
          p += strlen(p);
        }
      }

      q += sackoptlen - 2;
      len -= sackoptlen;
    } else if (opcode == 8) { /* Timestamp */
      if (len < 10)
        break; /* Timestamp option has 10 bytes */

      q++;
      memcpy(&tmpword1, q, 4);
      memcpy(&tmpword2, q + 4, 4);

      Snprintf(p, bufsize, "timestamp %u %u", ntohl(tmpword1),
               ntohl(tmpword2));
      bufsize -= strlen(p);
      p += strlen(p);

      q += 8;
      len -= 10;
    }

    ch = ',';
  }

  if (len > 0) {
    *result = '\0';
    return;
  }

  Snprintf(p, bufsize, ">");
}



/* A trivial function used with qsort to sort the routes by netmask */
static int nmaskcmp(const void *a, const void *b) {
  struct sys_route *r1 = (struct sys_route *) a;
  struct sys_route *r2 = (struct sys_route *) b;
  if (r1->netmask == r2->netmask) {
    /* Compare addresses of equal elements to make the sort stable, as suggested
       by the Glibc manual. */
    if (a < b)
      return -1;
    else if (a > b)
      return 1;
    else
      return 0;
  }
  if (ntohl(r1->netmask) > ntohl(r2->netmask))
    return -1;
  else
    return 1;
}



#if WIN32
static int collect_dnet_interfaces(const struct intf_entry *entry, void *arg) {
  struct dnet_collector_route_nfo *dcrn = (struct dnet_collector_route_nfo *) arg;
  bool primary_done;
  int num_aliases_done;

  primary_done = false;
  num_aliases_done = 0;
  while (!primary_done || num_aliases_done < entry->intf_alias_num) {
    /* Make sure we have room for the new route */
    if (dcrn->numifaces >= dcrn->capacity) {
      dcrn->capacity <<= 2;
      dcrn->ifaces = (struct interface_info *) safe_realloc(dcrn->ifaces,
        dcrn->capacity * sizeof(struct interface_info));
    }

    /* The first time through the loop we add the primary interface record.
       After that we add the aliases one at a time. */
    if (!primary_done) {
      if (entry->intf_addr.addr_type == ADDR_TYPE_IP) {
        addr_ntos(&entry->intf_addr, (struct sockaddr *) &dcrn->ifaces[dcrn->numifaces].addr);
        dcrn->ifaces[dcrn->numifaces].netmask_bits = entry->intf_addr.addr_bits;
      }
      primary_done = true;
    } else if (num_aliases_done < (int) entry->intf_alias_num) {
      if (entry->intf_alias_addrs[num_aliases_done].addr_type == ADDR_TYPE_IP) {
        addr_ntos(&entry->intf_alias_addrs[num_aliases_done], (struct sockaddr *) &dcrn->ifaces[dcrn->numifaces].addr);
        dcrn->ifaces[dcrn->numifaces].netmask_bits = entry->intf_alias_addrs[num_aliases_done].addr_bits;
      }
      num_aliases_done++;
    }

    /* OK, address/netmask found.  Let's get the name */
    Strncpy(dcrn->ifaces[dcrn->numifaces].devname, entry->intf_name,
      sizeof(dcrn->ifaces[dcrn->numifaces].devname));
    Strncpy(dcrn->ifaces[dcrn->numifaces].devfullname, entry->intf_name,
      sizeof(dcrn->ifaces[dcrn->numifaces].devfullname));

    /* Interface type */
    if (entry->intf_type == INTF_TYPE_ETH) {
      dcrn->ifaces[dcrn->numifaces].device_type = devt_ethernet;
      /* Collect the MAC address since this is ethernet */
      memcpy(dcrn->ifaces[dcrn->numifaces].mac, &entry->intf_link_addr.addr_eth.data, 6);
    } else if (entry->intf_type == INTF_TYPE_LOOPBACK) {
      dcrn->ifaces[dcrn->numifaces].device_type = devt_loopback;
    } else if (entry->intf_type == INTF_TYPE_TUN) {
      dcrn->ifaces[dcrn->numifaces].device_type = devt_p2p;
    } else {
      dcrn->ifaces[dcrn->numifaces].device_type = devt_other;
    }

    dcrn->ifaces[dcrn->numifaces].mtu = entry->intf_mtu;

    /* Is the interface up and running? */
    dcrn->ifaces[dcrn->numifaces].device_up = (entry->intf_flags & INTF_FLAG_UP) ? true : false;

    /* For the rest of the information, we must open the interface directly ... */
    dcrn->numifaces++;
  }

  return 0;
}

/* Get a list of interfaces using dnet and intf_loop. */
static struct interface_info *getinterfaces_dnet(int *howmany, char *errstr, size_t errstrlen) {
  struct dnet_collector_route_nfo dcrn;
  intf_t *it;

  dcrn.routes = NULL;
  dcrn.numroutes = 0;
  dcrn.numifaces = 0;

  assert(howmany);

  /* Initialize the interface array. */
  dcrn.capacity = 16;
  dcrn.ifaces = (struct interface_info *) safe_zalloc(sizeof(struct interface_info) * dcrn.capacity);

  it = intf_open();
  if (!it){
    if(errstr) Snprintf(errstr, errstrlen, "%s: intf_open() failed", __func__);
    *howmany=-1;
    return NULL;
  }
  if (intf_loop(it, collect_dnet_interfaces, &dcrn) != 0){
    if(errstr) Snprintf(errstr, errstrlen, "%s: intf_loop() failed", __func__);
    *howmany=-1;
    return NULL;
  }
  intf_close(it);

  *howmany = dcrn.numifaces;
  return dcrn.ifaces;
}

#else /* !WIN32 */

/* Get a list of interfaces using ioctl(SIOCGIFCONF). */
static struct interface_info *getinterfaces_siocgifconf(int *howmany, char *errstr, size_t errstrlen) {
  struct interface_info *devs;
  int count = 0;
  int capacity = 0;
  struct ifconf ifc;
  struct ifreq *ifr;
  int sd;
  int len;
  assert(howmany);
  capacity = 16;
  devs = (struct interface_info *) safe_zalloc(sizeof(struct interface_info) * capacity);

  /* Dummy socket for ioctl */
  sd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sd < 0){
    if(errstr) Snprintf(errstr, errstrlen, "socket in %s", __func__); 
    *howmany=-1;
    return NULL;
  }

  ifc.ifc_len = 20480;
  ifc.ifc_buf = (char *) safe_zalloc(ifc.ifc_len);
  /* Returns an array of struct ifreq in ifc.ifc_req, which is a union with
     ifc.ifc_buf. */
  if (ioctl(sd, SIOCGIFCONF, &ifc) < 0){
    if(errstr) Snprintf(errstr, errstrlen, "Failed to determine your configured interfaces!\n");
    *howmany=-1;
    return NULL;
  }
  if (ifc.ifc_len == 0){
    if(errstr) Snprintf(errstr, errstrlen, "%s: SIOCGIFCONF claims you have no network interfaces!\n", __func__);
    *howmany=-1;
    return NULL;
  }
  ifr = ifc.ifc_req;

  for (ifr = ifc.ifc_req;
       ifr && ifr->ifr_name[0] && (void *) ifr < (void *)((char *) ifc.ifc_buf + ifc.ifc_len);
       ifr = (struct ifreq *) ((char *) ifr + len)) {
    struct sockaddr_in *sin;
    struct ifreq tmpifr;
    u16 ifflags;
    int rc;
    char *p;

    len = sizeof(struct ifreq);
#if HAVE_SOCKADDR_SA_LEN
    /* Some platforms (such as FreeBSD) have an sa_len member that may make the
       ifr longer than sizeof(struct ifreq). */
    if (ifr->ifr_addr.sa_len > sizeof(ifr->ifr_ifru))
      len += ifr->ifr_addr.sa_len - sizeof(ifr->ifr_ifru);
#endif

    /* skip any device with no name */
    if (ifr->ifr_name[0] == '\0')
      continue;

    /* We currently only handle IPv4 */
    sin = (struct sockaddr_in *) &ifr->ifr_addr;
    if (sin->sin_family != AF_INET)
      continue;

    /* Make room for this new interface if necessary. */
    if (count >= capacity) {
      capacity <<= 2;
      devs = (struct interface_info *) safe_realloc(devs, sizeof(struct interface_info) * capacity);
    }

    /* We know the address, put it in the array. */
    memcpy(&(devs[count].addr), sin, MIN(sizeof(devs[count].addr), sizeof(*sin)));
    Strncpy(devs[count].devname, ifr->ifr_name, sizeof(devs[count].devname));
    Strncpy(devs[count].devfullname, ifr->ifr_name, sizeof(devs[count].devfullname));
    /* devname isn't allowed to have alias qualification */
    p = strchr(devs[count].devname, ':');
    if (p != NULL)
      *p = '\0';

    /* Use tmpifr for further ioctl requests. We're going to make a bunch of
       ioctl calls to learn about the interface and set fields in devs[count].

       The Linux netdevice(7) man page says that you only have to set ifr_name
       before making the ioctl, but perhaps other platforms need ifr_addr to be
       set too. ifr_name will persist but ifr_addr is in a union with the ioctl
       return value, so it has to be reset before every call. The general
       pattern is memcpy, then ioctl. */
    Strncpy(tmpifr.ifr_name, ifr->ifr_name, sizeof(tmpifr.ifr_name));

    /* Look up the netmask. Note setting of ifr_addr. */
    memcpy(&tmpifr.ifr_addr, sin, MIN(sizeof(tmpifr.ifr_addr), sizeof(*sin)));
    rc = ioctl(sd, SIOCGIFNETMASK, &tmpifr);
    if (rc < 0 && errno != EADDRNOTAVAIL){
      if(errstr) Snprintf(errstr, errstrlen, "Failed to determine the netmask of %s!", tmpifr.ifr_name);
      *howmany=-1;
      return NULL;
    }
    else if (rc < 0)
      devs[count].netmask_bits = 32;
    else {
      /* We would use ifr_netmask, but that's only on Linux, so use ifr_addr
         which shares the same memory space in a union. */
      addr_stob(&(tmpifr.ifr_addr), &devs[count].netmask_bits);
    }

    /* Now we need to determine the device type ... this technique is kinda iffy
       ... may not be portable. */
    /* Get the flags. */
    memcpy(&tmpifr.ifr_addr, sin, MIN(sizeof(tmpifr.ifr_addr), sizeof(*sin)));
    rc = ioctl(sd, SIOCGIFFLAGS, &tmpifr);
    if (rc < 0){
      if(errstr) Snprintf(errstr, errstrlen, "Failed to get IF Flags for device %s", ifr->ifr_name);
      *howmany=-1;
      return NULL;
    }
    ifflags = tmpifr.ifr_flags;

    if (ifflags & IFF_LOOPBACK) {
      devs[count].device_type = devt_loopback;
    } else if (ifflags & IFF_BROADCAST) {
      devs[count].device_type = devt_ethernet;

      /* If the device type is ethernet, get the MAC address. */
#ifdef SIOCGIFHWADDR
      memcpy(&tmpifr.ifr_addr, sin, MIN(sizeof(tmpifr.ifr_addr), sizeof(*sin)));
      rc = ioctl(sd, SIOCGIFHWADDR, &tmpifr);
      if (rc < 0 && errno != EADDRNOTAVAIL){
         if(errstr) Snprintf(errstr, errstrlen, "Failed to determine the MAC address of %s!", tmpifr.ifr_name);
         *howmany=-1;
         return NULL;
      }
      else if (rc >= 0)
        memcpy(devs[count].mac, &tmpifr.ifr_addr.sa_data, 6);
#else
      /* Let's just let libdnet handle it ... */
      eth_t *ethsd = eth_open_cached(devs[count].devname);
      eth_addr_t ethaddr;

      if (!ethsd) {
        netutil_error("Warning: Unable to open interface %s -- skipping it.", devs[count].devname);
        continue;
      }
      if (eth_get(ethsd, &ethaddr) != 0) {
        netutil_error("Warning: Unable to get hardware address for interface %s -- skipping it.", devs[count].devname);
        continue;
      }
      memcpy(devs[count].mac, ethaddr.data, 6);
#endif /*SIOCGIFHWADDR*/
    } else if (ifflags & IFF_POINTOPOINT) {
      devs[count].device_type = devt_p2p;
    } else {
      devs[count].device_type = devt_other;
    }

    if (ifflags & IFF_UP)
      devs[count].device_up = 1;
    else
      devs[count].device_up = 0;

#ifdef SIOCGIFMTU
    memcpy(&tmpifr.ifr_addr, sin, MIN(sizeof(tmpifr.ifr_addr), sizeof(*sin)));
    rc = ioctl(sd, SIOCGIFMTU, &tmpifr);
    if (rc < 0) {
      if(errstr) Snprintf(errstr, errstrlen, "Failed to determine the mtu of %s!", tmpifr.ifr_name);
      *howmany=-1;
      return NULL;
    } else {
#ifdef ifr_mtu
      devs[count].mtu = tmpifr.ifr_mtu;
#else
      /* Some systems lack ifr_mtu and a common solution (see pcap, dnet and
       * others) is using ifr_metric instead
       */
      devs[count].mtu = tmpifr.ifr_metric;
#endif
    }
#else
    devs[count].mtu = 0;
#endif

    /* All done with this interface. Increase the count. */
    count++;
  }
  free(ifc.ifc_buf);
  close(sd);

  *howmany = count;
  return devs;
}
#endif

/* Returns an allocated array of struct interface_info representing the
   available interfaces. The number of interfaces is returned in *howmany. This
   function just does caching of results; the real work is done in
   getinterfaces_dnet() or getinterfaces_siocgifconf().
   On error, NULL is returned, howmany is set to -1 and the supplied
   error buffer "errstr", if not NULL, will contain an error message. */
struct interface_info *getinterfaces(int *howmany, char *errstr, size_t errstrlen) {
  static int initialized = 0;
  static struct interface_info *mydevs;
  static int numifaces = 0;

  if (!initialized) {
#if WIN32
    /* On Win32 we just use Dnet to determine the interface list */
    mydevs = getinterfaces_dnet(&numifaces, errstr, errstrlen);
#else
    mydevs = getinterfaces_siocgifconf(&numifaces, errstr, errstrlen);
#endif
    initialized = 1;
  }

  /* These will propagate any error produced in getinterfaces_xxxx() to
   * the caller. */
  if (howmany)
    *howmany = numifaces;
  return mydevs;
}


/* The 'dev' passed in must be at least 32 bytes long. Returns 0 on success. */
int ipaddr2devname(char *dev, const struct in_addr *addr) {
  struct interface_info *ifaces;
  struct sockaddr_in *sin;
  int numifaces;
  int i;

  ifaces = getinterfaces(&numifaces, NULL, 0);

  if (ifaces == NULL)
    return -1;

  for (i = 0; i < numifaces; i++) {
    sin = (struct sockaddr_in *) &ifaces[i].addr;
    if (sin->sin_family != AF_INET)
      continue;
    if (addr->s_addr == sin->sin_addr.s_addr) {
      Strncpy(dev, ifaces[i].devname, 32);
      return 0;
    }
  }

  return -1;
}

int devname2ipaddr(char *dev, struct in_addr *addr) {
  struct interface_info *mydevs;
  struct sockaddr_in *s;
  int numdevs;
  int i;
  mydevs = getinterfaces(&numdevs, NULL, 0);

  if (!mydevs)
    return -1;

  for (i = 0; i < numdevs; i++) {
    s = (struct sockaddr_in *) &mydevs[i].addr;
    if (s->sin_family != AF_INET) /* Currently we only support IPv4 */
      continue;
    if (!strcmp(dev, mydevs[i].devfullname)) {
      memcpy(addr, (char *) &s->sin_addr, sizeof(struct in_addr));
      return 0;
    }
  }
  return -1;
}

/* Looks for an interface with the given name (iname), and returns the
   corresponding interface_info if found.  Will accept a match of
   devname or devfullname.  Returns NULL if none found */
struct interface_info *getInterfaceByName(const char *iname) {
  struct interface_info *ifaces;
  int numifaces = 0;
  int ifnum;

  ifaces = getinterfaces(&numifaces, NULL, 0);

  for (ifnum = 0; ifnum < numifaces; ifnum++) {
    if (strcmp(ifaces[ifnum].devfullname, iname) == 0 ||
        strcmp(ifaces[ifnum].devname, iname) == 0)
      return &ifaces[ifnum];
  }

  return NULL;
}



/* Read system routes from a handle to a /proc/net/route file. */
static struct sys_route *getsysroutes_proc(FILE *routefp, int *howmany, char *errstr, size_t errstrlen) {
  struct sys_route *routes = NULL;
  int route_capacity = 128;
  struct interface_info *ifaces;
  char buf[1024];
  char iface[16];
  char *p, *endptr;
  struct interface_info *ii;
  u32 routeaddr, mask;
  struct sockaddr_in *sin;
  int numifaces = 0, numroutes = 0;
  int i;
  assert(howmany);
  
  /* Obtain list of system network interfaces */
  if( (ifaces=getinterfaces(&numifaces, errstr, errstrlen)) == NULL ){
    *howmany=-1;
    return NULL;
  }
  routes = (struct sys_route *) safe_zalloc(route_capacity * sizeof(struct sys_route));

  /* Kill the first line (column headers) */
  errno = 0;
  if (fgets(buf, sizeof(buf), routefp) == NULL) {
    if (errno){
      if(errstr) Snprintf(errstr, errstrlen, "Read error in /proc/net/route");
    }else{
      if(errstr) Snprintf(errstr, errstrlen, "Premature EOF in /proc/net/route");
    }
    *howmany=-1;
    return NULL;
  }
  
  while (fgets(buf, sizeof(buf), routefp)) {
    p = strtok(buf, " \t\n");
    if (!p) {
      netutil_error("Could not find interface in /proc/net/route line");
      continue;
    }
    if (*p == '*')
      continue; /* Deleted route -- any other valid reason for a route to start with an asterict? */
    Strncpy(iface, p, sizeof(iface));
    p = strtok(NULL, " \t\n");
    if (!p) {
      netutil_error("Could not find destination in /proc/net/route line");
      continue;
    }
    endptr = NULL;
    routes[numroutes].dest = strtoul(p, &endptr, 16);
    if (!endptr || *endptr) {
      netutil_error("Failed to determine Destination from /proc/net/route");
      continue;
    }

    /* Now for the gateway */
    p = strtok(NULL, " \t\n");
    if (!p) {
      netutil_error("Could not find gateway in /proc/net/route line");
      continue;
    }
    endptr = NULL;
    routes[numroutes].gw.s_addr = strtoul(p, &endptr, 16);
    if (!endptr || *endptr) {
      netutil_error("Failed to determine gw for %s from /proc/net/route", iface);
    }
    for (i = 0; i < 5; i++) {
      p = strtok(NULL, " \t\n");
      if (!p)
        break;
    }
    if (!p) {
      netutil_error("Failed to find field %d in /proc/net/route", i + 2);
      continue;
    }
    endptr = NULL;
    routes[numroutes].netmask = strtoul(p, &endptr, 16);
    if (!endptr || *endptr) {
      netutil_error("Failed to determine mask from /proc/net/route");
      continue;
    }
    for (i = 0; i < numifaces; i++) {
      if (!strcmp(iface, ifaces[i].devfullname)) {
        routes[numroutes].device = &ifaces[i];
        break;
      }
    }
    /* If device name in the route file does not match the full name (including
       alias extension) of any interface, then try to find at least an alias of
       the proper interface. */
    if (i == numifaces) {
      for (i = 0; i < numifaces; i++) {
        if (!strcmp(iface, ifaces[i].devname)) {
          routes[numroutes].device = &ifaces[i];
          break;
        }
      }
    }
    if (i == numifaces) {
      netutil_error("Failed to find device %s which was referenced in /proc/net/route", iface);
      continue;
    }

    /* Now to deal with some alias nonsense ... at least on Linux
       this file will just list the short name, even though IP
       information (such as source address) from an alias must be
       used.  So if the purported device can't reach the gateway
       (or destination address for directly connected routes),
       try to find a device that starts with the same short
       devname, but can (e.g. eth0 -> eth0:3) */
    if (routes[numroutes].gw.s_addr != 0)
        routeaddr = routes[numroutes].gw.s_addr;
    else
        routeaddr = routes[numroutes].dest;
    ii = &ifaces[i];
    mask = htonl((unsigned long) (0 - 1) << (32 - ii->netmask_bits));
    sin = (struct sockaddr_in *) &ii->addr;
    if ((sin->sin_addr.s_addr & mask) != (routeaddr & mask)) {
      for (i = 0; i < numifaces; i++) {
        if (ii == &ifaces[i])
          continue;
        if (strcmp(ii->devname, ifaces[i].devname) == 0) {
          sin = (struct sockaddr_in *) &ifaces[i].addr;
          if ((sin->sin_addr.s_addr & mask) == (routeaddr & mask)) {
            routes[numroutes].device = &ifaces[i];
          }
        }
      }
    }

    numroutes++;
    if (numroutes >= route_capacity) {
      route_capacity <<= 2;
      routes = (struct sys_route *) safe_realloc(routes, route_capacity * sizeof(struct sys_route));
    }
  }

  *howmany = numroutes;
  return routes;
}


/* This is a helper for getsysroutes_dnet. Once the table of routes is in
   place, this function assigns each to an interface and removes any routes
   that can't be assigned. */
static struct dnet_collector_route_nfo *sysroutes_dnet_find_interfaces(struct dnet_collector_route_nfo *dcrn) 
{
  struct interface_info *ifaces;
  u32 mask;
  struct sockaddr_in *sin;
  int numifaces = 0;
  int i, j;
  int changed=0;

  if( (ifaces=getinterfaces(&numifaces, NULL, 0))==NULL )
    return NULL;
  for (i = 0; i < dcrn->numroutes; i++) {
    /* First we match up routes whose gateway address directly matches the
       address of an interface. */
    for (j = 0; j < numifaces; j++) {
      sin = (struct sockaddr_in *) &ifaces[j].addr;
      mask =
          htonl((unsigned long) (0 - 1) << (32 - ifaces[j].netmask_bits));
      if ((sin->sin_addr.s_addr & mask) ==
          (dcrn->routes[i].gw.s_addr & mask)) {
        dcrn->routes[i].device = &ifaces[j];
        break;
      }
    }
  }

  /* Find any remaining routes that don't yet have an interface, and try to
     match them up with the interface of another route. This handles "two-step"
     routes like sometimes exist with PPP, where the gateway address of the
     default route doesn't match an interface address, but the gateway address
     goes through another route that does have an interface. */

  do {
    changed = 0;
    for (i = 0; i < dcrn->numroutes; i++) {
      if (dcrn->routes[i].device != NULL)
        continue;
      /* Does this route's gateway go through another route with an assigned
         interface? */
      for (j = 0; j < dcrn->numroutes; j++) {
        if (dcrn->routes[i].gw.s_addr == dcrn->routes[j].dest
            && dcrn->routes[j].device != NULL) {
          dcrn->routes[i].device = dcrn->routes[j].device;
          changed = 1;
        }
      }
    }
  } while (changed);

  /* Cull any routes that still don't have an interface. */
  i = 0;
  while (i < dcrn->numroutes) {
    if (dcrn->routes[i].device == NULL) {
      char destbuf[INET6_ADDRSTRLEN];
      char gwbuf[INET6_ADDRSTRLEN];
      struct in_addr ia; 

      ia.s_addr = dcrn->routes[i].dest;
      strncpy(destbuf, inet_ntoa(ia), sizeof(destbuf));
      strncpy(gwbuf, inet_ntoa(dcrn->routes[i].gw), sizeof(gwbuf));
      netutil_error("WARNING: Unable to find appropriate interface for system route to %s/%u gw %s",
      	destbuf, dcrn->routes[i].netmask, gwbuf);
      /* Remove this entry from the table. */
      memmove(dcrn->routes + i, dcrn->routes + i + 1, sizeof(dcrn->routes[0]) * (dcrn->numroutes - i - 1));
      dcrn->numroutes--;
    } else {
      i++;
    }
  }

  return dcrn;
}


/* This is the callback for the call to route_loop in getsysroutes_dnet. It
   takes a route entry and adds it into the dnet_collector_route_nfo struct. */
static int collect_dnet_routes(const struct route_entry *entry, void *arg) {
  struct dnet_collector_route_nfo *dcrn = (struct dnet_collector_route_nfo *) arg;
  /* Make sure that it is the proper type of route ... */
  if (entry->route_dst.addr_type != ADDR_TYPE_IP || entry->route_gw.addr_type != ADDR_TYPE_IP)
    return 0; /* Not interested in IPv6 routes at the moment ... */

  /* Make sure we have room for the new route */
  if (dcrn->numroutes >= dcrn->capacity) {
    dcrn->capacity <<= 2;
    dcrn->routes = (struct sys_route *) safe_realloc(dcrn->routes, dcrn->capacity * sizeof(struct sys_route));
  }

  /* Now for the important business */
  dcrn->routes[dcrn->numroutes].dest = entry->route_dst.addr_ip;
  addr_btom(entry->route_dst.addr_bits,
            &dcrn->routes[dcrn->numroutes].netmask,
            sizeof(dcrn->routes[dcrn->numroutes].netmask));
  dcrn->routes[dcrn->numroutes].gw.s_addr = entry->route_gw.addr_ip;
  dcrn->numroutes++;

  return 0;
}


/* Read system routes via libdnet. */
static struct sys_route *getsysroutes_dnet(int *howmany, char *errstr, size_t errstrlen) {
  struct dnet_collector_route_nfo dcrn;

  dcrn.capacity = 128;
  dcrn.routes = (struct sys_route *) safe_zalloc(dcrn.capacity * sizeof(struct sys_route));
  dcrn.numroutes = 0;
  dcrn.ifaces = NULL;
  dcrn.numifaces = 0;
  assert(howmany);
  route_t *dr = route_open();
  
  if (!dr){
    if(errstr) Snprintf(errstr, errstrlen, "%s: route_open() failed", __func__);
    *howmany=-1;
    return NULL;
  }
  if (route_loop(dr, collect_dnet_routes, &dcrn) != 0) {
    if(errstr) Snprintf(errstr, errstrlen, "%s: route_loop() failed", __func__);
    *howmany=-1;
    return NULL;
  }
  route_close(dr);

  /* Now match up the routes to interfaces. */
  if( sysroutes_dnet_find_interfaces(&dcrn) == NULL ){
    if(errstr) Snprintf(errstr, errstrlen, "%s: sysroutes_dnet_find_interfaces() failed", __func__);
    return NULL;
  }

  *howmany = dcrn.numroutes;
  return dcrn.routes;
}


/* Parse the system routing table, converting each route into a
   sys_route entry.  Returns an array of sys_routes.  numroutes is set
   to the number of routes in the array.  The routing table is only
   read the first time this is called -- later results are cached.
   The returned route array is sorted by netmask with the most
   specific matches first.
   On error, NULL is returned, howmany is set to -1 and the supplied
   error buffer "errstr", if not NULL, will contain an error message. */
struct sys_route *getsysroutes(int *howmany, char *errstr, size_t errstrlen) {
  static struct sys_route *routes = NULL;
  static int numroutes = 0;
  FILE *routefp;
  assert(howmany);
  
  if (routes != NULL) {
    /* We have it cached. */
    *howmany = numroutes;
    return routes;
  }

  /* First let us try Linux-style /proc/net/route */
  routefp = fopen("/proc/net/route", "r");
  if (routefp) {
    routes = getsysroutes_proc(routefp, howmany, errstr, errstrlen);
    fclose(routefp);
  } else {
    routes = getsysroutes_dnet(howmany, errstr, errstrlen);
  }

  /* Check if we managed to get the routes and sort them if we did */
  if(routes==NULL){
    *howmany=-1;
    return NULL;
  }else{
    numroutes = *howmany;
    /* Ensure that the route array is sorted by netmask */
    qsort(routes, numroutes, sizeof(routes[0]), nmaskcmp);
  }
  return routes;
}


/* Tries to determine whether the supplied address corresponds to
 * localhost. (eg: the address is something like 127.x.x.x, the address
 * matches one of the local network interfaces' address, etc).
 * Returns 1 if the address is thought to be localhost and 0 otherwise */
int islocalhost(const struct in_addr *const addr) {
  char dev[128];
  /* If it is 0.0.0.0 or starts with 127 then it is 
     probably localhost */
  if ((addr->s_addr & htonl(0xFF000000)) == htonl(0x7F000000))
    return 1;

  if (!addr->s_addr)
    return 1;

  /* If it is the same addy as a local interface, then it is
     probably localhost */
  if (ipaddr2devname(dev, addr) != -1)
    return 1;

  /* OK, so to a first approximation, this addy is probably not
     localhost */
  return 0;
}


/* Determines whether the supplied address corresponds to a private,
 * non-Internet-routable address. See RFC1918 for details.
 * Returns 1 if the address is private or 0 otherwise. */
int isipprivate(const struct in_addr *const addr) {
  char *ipc;
  unsigned char i1, i2;

  if (!addr)
    return 0;

  ipc = (char *) &(addr->s_addr);
  i1 = ipc[0];
  i2 = ipc[1];

  /* 10.0.0.0/8 */
  if (i1 == 10)
    return 1;

  /* 172.16.0.0/12 */
  if (i1 == 172 && i2 >= 16 && i2 <= 31)
    return 1;

  /* 192.168.0.0/16 */
  if (i1 == 192 && i2 == 168)
    return 1;

  return 0;
}


char *nexthdrtoa(u8 nextheader, int acronym){

static char buffer[129];
memset(buffer, 0, 129);


switch(nextheader){

    case 0: 
        if(acronym)
            strncpy(buffer, "HOPOPT", 128);
        else
            strncpy(buffer, "IPv6 Hop-by-Hop Option", 128);
    break;


    case 1: 
        if(acronym)
            strncpy(buffer, "ICMP", 128);
        else
            strncpy(buffer, "Internet Control Message", 128);
    break;


    case 2: 
        if(acronym)
            strncpy(buffer, "IGMP", 128);
        else
            strncpy(buffer, "Internet Group Management", 128);
    break;


    case 4: 
        if(acronym)
            strncpy(buffer, "IP", 128);
        else
            strncpy(buffer, "IP in IP (encapsulation)", 128);
    break;


    case 6: 
        if(acronym)
            strncpy(buffer, "TCP", 128);
        else
            strncpy(buffer, "Transmission Control Protocol", 128);
    break;


    case 8: 
        if(acronym)
            strncpy(buffer, "EGP", 128);
        else
            strncpy(buffer, "Exterior Gateway Protocol", 128);
    break;


    case 9: 
        if(acronym)
            strncpy(buffer, "IGP", 128);
        else
            strncpy(buffer, "Interior Gateway Protocol", 128);
    break;


    case 17: 
        if(acronym)
            strncpy(buffer, "UDP", 128);
        else
            strncpy(buffer, "User Datagram", 128);
    break;


    case 41: 
        if(acronym)
            strncpy(buffer, "IPv6", 128);
        else
            strncpy(buffer, "Internet Protocol version 6", 128);
    break;


    case 43: 
        if(acronym)
            strncpy(buffer, "IPv6-Route", 128);
        else
            strncpy(buffer, "Routing Header for IPv6", 128);
    break;


    case 44: 
        if(acronym)
            strncpy(buffer, "IPv6-Frag", 128);
        else
            strncpy(buffer, "Fragment Header for IPv6", 128);
    break;


    case 50: 
        if(acronym)
            strncpy(buffer, "ESP", 128);
        else
            strncpy(buffer, "Encap Security Payload", 128);
    break;


    case 51: 
        if(acronym)
            strncpy(buffer, "AH", 128);
        else
            strncpy(buffer, "Authentication Header", 128);
    break;


    case 55: 
        if(acronym)
            strncpy(buffer, "MOBILE", 128);
        else
            strncpy(buffer, "IP Mobility", 128);
    break;


    case 58: 
        if(acronym)
            strncpy(buffer, "IPv6-ICMP", 128);
        else
            strncpy(buffer, "ICMP for IPv6", 128);
    break;


    case 59: 
        if(acronym)
            strncpy(buffer, "IPv6-NoNxt", 128);
        else
            strncpy(buffer, "No Next Header for IPv6", 128);
    break;


    case 60: 
        if(acronym)
            strncpy(buffer, "IPv6-Opts", 128);
        else
            strncpy(buffer, "Destination Options for IPv6", 128);
    break;


    case 70: 
        if(acronym)
            strncpy(buffer, "VISA", 128);
        else
            strncpy(buffer, "VISA Protocol", 128);
    break;


    case 88: 
        if(acronym)
            strncpy(buffer, "EIGRP", 128);
        else
            strncpy(buffer, "Enhanced Interior Gateway Routing Protocol ", 128);
    break;


    case 94: 
        if(acronym)
            strncpy(buffer, "IPIP", 128);
        else
            strncpy(buffer, "IP-within-IP Encapsulation Protocol", 128);
    break;


    case 132: 
        if(acronym)
            strncpy(buffer, "SCTP", 128);
        else
            strncpy(buffer, "Stream Control Transmission Protocol", 128);
    break;


    case 133: 
        if(acronym)
            strncpy(buffer, "FC", 128);
        else
            strncpy(buffer, "Fibre Channel", 128);
    break;


    case 135: 
        if(acronym)
            strncpy(buffer, "MH", 128);
        else
            strncpy(buffer, "Mobility Header", 128);
    break;

  } /* End of switch */


   return buffer;
   
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
char *format_ip_options(u8* ipopt, int ipoptlen) {
  char ipstring[32];
  int option_type = UNKNOWN;// option type
  int option_len  = 0; // option length
  int option_pt   = 0; // option pointer
  int option_fl   = 0;  // option flag
  u8 *tptr;		// temp pointer
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
	  STRAPP("%u", ntohl(*tint));

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
    	  STRAPP("id=%i", option_pt);
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
const char *ippackethdrinfo(const u8 *packet, u32 len, int detail) {
  struct ip *ip = (struct ip *) packet; /* IPv4 header structure.            */
  struct tcp_hdr *tcp = NULL;           /* TCP header structure.             */
  struct udp_hdr *udp = NULL;           /* UDP header structure.             */
  struct sctp_hdr *sctp = NULL;         /* SCTP header structure.            */
  static char protoinfo[1024] = "";     /* Stores final info string.         */
  char ipinfo[512] = "";                /* Temp info about IP.               */
  char icmpinfo[512] = "";              /* Temp info about ICMP.             */
  char icmptype[128]="";                /* Temp info about ICMP type & code  */
  char icmpfields[256]="";              /* Temp info for various ICMP fields */
  char fragnfo[64] = "";                /* Temp info about fragmentation.    */
  char srchost[INET6_ADDRSTRLEN] = "";  /* Src IP in dot-decimal notation.   */
  char dsthost[INET6_ADDRSTRLEN] = "";  /* Dst IP in dot-decimal notation.   */
  struct in_addr saddr, daddr;          /* Src and Dst IPs in binary.        */
  char *p = NULL;                       /* Aux pointer.                      */
  int frag_off = 0;                     /* To compute IP fragment offset.    */
  int more_fragments = 0;               /* True if IP MF flag is set.        */
  int dont_fragment = 0;                /* True if IP DF flag is set.        */
  int reserved_flag = 0;                /* True if IP Reserved flag is set.  */
  size_t iphdrlen=0;                    /* Length of the IP (4 or 6) header  */
  u8 nextproto=0;                       /* Protocol after IP (4 or 6) header */
  
  /* Ensure IP version makes sense */
  if (ip->ip_v != 4 && ip->ip_v != 6 )
    return "BOGUS!  IP Version in packet is not 4";


  /* Ensure we end up with a valid detail number */
  if( detail!=LOW_DETAIL && detail!=MEDIUM_DETAIL && detail!=HIGH_DETAIL)
    detail=LOW_DETAIL;

/* IP INFORMATION ************************************************************/
if( ip->ip_v == 4 ){ /* IPv4 */

  if (len < 20)
    return "BOGUS!  Packet too short.";
  else{
     iphdrlen=ip->ip_hl * 4;
     nextproto=ip->ip_p;
  }

  /* Obtain IP source and destination info */
  saddr.s_addr = ip->ip_src.s_addr;
  daddr.s_addr = ip->ip_dst.s_addr;
  inet_ntop(AF_INET, &saddr, srchost, sizeof(srchost));
  inet_ntop(AF_INET, &daddr, dsthost, sizeof(dsthost));

  /* Compute fragment offset and check if flags are set */
  frag_off = 8 * (ntohs(ip->ip_off) & 8191) /* 2^13 - 1 */;
  more_fragments = ntohs(ip->ip_off) & IP_MF;
  dont_fragment = ntohs(ip->ip_off) & IP_DF;
  reserved_flag = ntohs(ip->ip_off) & IP_RF;

  /* Is this a fragmented packet? is it the last fragment? */
  if (frag_off || more_fragments) {
    Snprintf(fragnfo, sizeof(fragnfo), " frag offset=%d%s", frag_off, more_fragments ? "+" : "");
  }

  /* Create a string with information relevant to the specified level of detail */
  if( detail == LOW_DETAIL ){
      Snprintf(ipinfo, sizeof(ipinfo), "ttl=%d id=%d iplen=%d%s %s%s%s",
          ip->ip_ttl, ntohs(ip->ip_id), ntohs(ip->ip_len), fragnfo,
          ip->ip_hl==5?"":"ipopts={",
          ip->ip_hl==5?"":format_ip_options((u8*)ip + sizeof(struct ip), MIN((unsigned)(ip->ip_hl-5)*4,len-sizeof(struct ip))),
          ip->ip_hl==5?"":"}");
  }else if( detail == MEDIUM_DETAIL ){
      Snprintf(ipinfo, sizeof(ipinfo), "ttl=%d id=%d proto=%d csum=0x%04x iplen=%d%s %s%s%s",
          ip->ip_ttl, ntohs(ip->ip_id),
          ip->ip_p, ntohs(ip->ip_sum),
          ntohs(ip->ip_len), fragnfo,
          ip->ip_hl==5?"":"ipopts={",
          ip->ip_hl==5?"":format_ip_options((u8*)ip + sizeof(struct ip), MIN((unsigned)(ip->ip_hl-5)*4,len-sizeof(struct ip))),
          ip->ip_hl==5?"":"}");
  }else if( detail==HIGH_DETAIL ){
      Snprintf(ipinfo, sizeof(ipinfo), "ver=%d ihl=%d tos=0x%02x iplen=%d id=%d%s%s%s%s foff=%d%s ttl=%d proto=%d csum=0x%04x%s%s%s",
          ip->ip_v, ip->ip_hl,
          ip->ip_tos, ntohs(ip->ip_len),
          ntohs(ip->ip_id),
          (reserved_flag||dont_fragment||more_fragments) ? " flg=" : "",
          (reserved_flag)? "x" : "",
          (dont_fragment)? "D" : "",
          (more_fragments)? "M": "",
          frag_off, (more_fragments) ? "+" : "",
          ip->ip_ttl, ip->ip_p,
          ntohs(ip->ip_sum),
          ip->ip_hl==5?"":" ipopts={",
          ip->ip_hl==5?"":format_ip_options((u8*)ip + sizeof(struct ip), MIN((unsigned)(ip->ip_hl-5)*4,len-sizeof(struct ip))),
          ip->ip_hl==5?"":"}");
  }

}else{ /* IPv6 */

  /* I'd rather use a regular u8 pointer to access the IPv6 header because
   * it's surprinsingly easy to fuck the whole thing up using structures due
   * to the weird IPv6 field alignment and the f*** compiler padding structs
   * when it shouldn't. */
  u8  *ipv6pnt = (u8 *)packet;

  if (len < 40)
    return "BOGUS!  IPv6 Packet too short.";
  else{
     iphdrlen=40;
     nextproto=ipv6pnt[6];
  }

  /* Obtain IP source and destination info */
  struct in6_addr ip6_src;
  struct in6_addr ip6_dst;
  memcpy(ip6_src.s6_addr, &ipv6pnt[8], 16);
  memcpy(ip6_dst.s6_addr, &ipv6pnt[24], 16);
  inet_ntop(AF_INET6, &ip6_src, srchost, sizeof(srchost));
  inet_ntop(AF_INET6, &ip6_dst, dsthost, sizeof(dsthost));

  /* Obtain payload length, next protocol and hop limit */
  u16 *ipv6_pl = (u16 *)(&ipv6pnt[4]);
  u8  *ipv6_nh = (u8 *)(& ipv6pnt[6]);
  u8  *ipv6_hl = (u8 *)(& ipv6pnt[7]);


  /* Obtain flow label and traffic class */
  u32 *word = (u32 *)(&ipv6pnt[0]);
  u32 flow= ntohl( *word );

  u32 ip6_fl = flow & 0x000fffff;
  u32 ip6_tc = (flow & 0x0ff00000) >> 20;


  /* Create a string with information relevant to the specified level of detail */
  if( detail == LOW_DETAIL ){
      Snprintf(ipinfo, sizeof(ipinfo), "hopl=%d flow=%x payloadlen=%d",
          (*ipv6_hl), ip6_fl, ntohs(*ipv6_pl)
          );
  }else if( detail == MEDIUM_DETAIL ){
      Snprintf(ipinfo, sizeof(ipinfo), "hopl=%d tclass=%d flow=%x payloadlen=%d",
          (*ipv6_hl), ip6_tc, ip6_fl, ntohs(*ipv6_pl)
          );
  }else if( detail==HIGH_DETAIL ){
      Snprintf(ipinfo, sizeof(ipinfo), "ver=6, tclass=%x flow=%x payloadlen=%d nh=%s hopl=%d ",
          ip6_tc, ip6_fl, ntohs(*ipv6_pl),
          nexthdrtoa(*ipv6_nh, 1), *ipv6_hl
          );
  }

}


/* TCP INFORMATION ***********************************************************/
  if (nextproto == IPPROTO_TCP) {
    char tflags[10];
    char tcpinfo[64] = "";
    char buf[32];
    char tcpoptinfo[256] = "";
    tcp = (struct tcp_hdr *)  (packet + iphdrlen);


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
    if ( (frag_off > 8) || (len < (u32) iphdrlen + 8) ){    
      Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? ?? %s (incomplete)",
        srchost, dsthost, ipinfo);
    }

    /* CASE 2: where we are missing the first 8 bytes of the TCP header but we
     * have, at least, the next 8 bytes so we can see the ACK number, the
     * flags and window size. */      
    else if ( (frag_off == 8) && (len >= (u32) iphdrlen + 8)) {

      tcp = (struct tcp_hdr *)((u8 *) tcp - frag_off); // ugly?

      /* TCP Flags */
      p = tflags;
      /* These are basically in tcpdump order */
      if (tcp->th_flags & TH_SYN) *p++ = 'S';
      if (tcp->th_flags & TH_FIN) *p++ = 'F';
      if (tcp->th_flags & TH_RST) *p++ = 'R';
      if (tcp->th_flags & TH_PUSH) *p++ = 'P';
      if (tcp->th_flags & TH_ACK){ *p++ = 'A';
            Snprintf(tcpinfo, sizeof(tcpinfo), " ack=%lu",
                (unsigned long) ntohl(tcp->th_ack));
      }
      if (tcp->th_flags & TH_URG) *p++ = 'U';
      if (tcp->th_flags & TH_ECE) *p++ = 'E'; /* rfc 2481/3168 */
      if (tcp->th_flags & TH_CWR) *p++ = 'C'; /* rfc 2481/3168 */
      *p++ = '\0';

      /* TCP Options */
      if((u32) tcp->th_off * 4 > sizeof(struct tcp_hdr)) {
        if(len < (u32) iphdrlen + (u32) tcp->th_off * 4 - frag_off) {
          Snprintf(tcpoptinfo, sizeof(tcpoptinfo), "option incomplete");
        } else {
          tcppacketoptinfo((u8*) tcp + sizeof(struct tcp_hdr),
                     tcp->th_off*4 - sizeof(struct tcp_hdr),
                     tcpoptinfo, sizeof(tcpoptinfo));
        }
      }

      /* Create a string with TCP information relevant to the specified level of detail */
      if( detail == LOW_DETAIL ){
      Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s %s %s %s",
               srchost, dsthost, tflags, ipinfo, tcpinfo, tcpoptinfo);          
      }else if( detail == MEDIUM_DETAIL ){
      Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s ack=%ul win=%hu %s IP [%s]",
               srchost, dsthost, tflags,
               ntohl(tcp->th_ack), ntohs(tcp->th_win),
               tcpoptinfo, ipinfo);
      }else if( detail==HIGH_DETAIL ){
          if( len >= (u32) iphdrlen + 12 ){ /* We have at least bytes 8-20 */
            Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:?? > %s:?? %s seq=%lu ack=%lu off=%d res=%d win=%hu csum=0x%04X urp=%d%s%s] IP [%s]",
               srchost, dsthost, tflags,
               (unsigned long) ntohl(tcp->th_seq),
               (unsigned long) ntohl(tcp->th_ack),
               (u8)tcp->th_off, (u8)tcp->th_x2, ntohs(tcp->th_win),
               ntohs(tcp->th_sum), ntohs(tcp->th_urp),
               (tcpoptinfo[0]!='\0') ? " " : "",
               tcpoptinfo, ipinfo );
           }else{ /* We only have bytes 8-16 */
                Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s ack=%ul win=%hu %s IP [%s]",
                    srchost, dsthost, tflags,
                    ntohl(tcp->th_ack), ntohs(tcp->th_win),
                    tcpoptinfo, ipinfo);
            }
      }

    }
    
    /* CASE 3: where the IP packet is not a fragment but for some reason, we
     * don't have the entire TCP header, just part of it.*/
    else if ((len > (u32)iphdrlen) && (len < (u32) iphdrlen + 20)) {
     
        /* We only have the first 32 bits: source and dst port */
        if( (len >= (u32)iphdrlen + 4) && (len < (u32)iphdrlen + 8) ){
            Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%d > %s:%d ?? (incomplete) %s",
                     srchost, ntohs(tcp->th_sport), dsthost, ntohs(tcp->th_dport), ipinfo);
        }

         /* We only have the first 64 bits: ports and seq number */
        if( (len >= (u32)iphdrlen + 8) && (len < (u32)iphdrlen + 12) ) {
            Snprintf(tcpinfo, sizeof(tcpinfo), "TCP %s:%d > %s:%d ?? seq=%lu (incomplete) %s",
                     srchost, ntohs(tcp->th_sport), dsthost,
                     ntohs(tcp->th_dport), (unsigned long) ntohl(tcp->th_seq), ipinfo);
        }
        
        /* We only have the first 96 bits: ports, seq and ack number */
        if( (len >= (u32)iphdrlen + 12) && (len < (u32)iphdrlen + 16) ) {
            if(detail == LOW_DETAIL){ /* We don't print ACK in low detail */
                Snprintf(tcpinfo, sizeof(tcpinfo), "TCP %s:%d > %s:%d seq=%lu (incomplete), %s",
                         srchost, ntohs(tcp->th_sport), dsthost,
                         ntohs(tcp->th_dport), (unsigned long) ntohl(tcp->th_seq), ipinfo);
            }else{
                Snprintf(tcpinfo, sizeof(tcpinfo), "TCP [%s:%d > %s:%d seq=%lu ack=%lu (incomplete)] IP [%s]",
                         srchost, ntohs(tcp->th_sport), dsthost,
                         ntohs(tcp->th_dport), (unsigned long) ntohl(tcp->th_seq),
                         (unsigned long) ntohl(tcp->th_ack), ipinfo);
            }
        }

        /* We are missing the last 32 bits (checksum and urgent pointer) */
        if( (len >= (u32)iphdrlen + 16) && (len < (u32)iphdrlen + 20) ) {
            p = tflags;
            /* These are basically in tcpdump order */
            if (tcp->th_flags & TH_SYN) *p++ = 'S';
            if (tcp->th_flags & TH_FIN) *p++ = 'F';
            if (tcp->th_flags & TH_RST) *p++ = 'R';
            if (tcp->th_flags & TH_PUSH) *p++ = 'P';
            if (tcp->th_flags & TH_ACK){ *p++ = 'A';
            Snprintf(buf, sizeof(buf), " ack=%lu",
                 (unsigned long) ntohl(tcp->th_ack));
            strncat(tcpinfo, buf, sizeof(tcpinfo) - strlen(tcpinfo) - 1);
            }
            if (tcp->th_flags & TH_URG) *p++ = 'U';
            if (tcp->th_flags & TH_ECE) *p++ = 'E'; /* rfc 2481/3168 */
            if (tcp->th_flags & TH_CWR) *p++ = 'C'; /* rfc 2481/3168 */
            *p++ = '\0';


            /* Create a string with TCP information relevant to the specified level of detail */
            if(detail == LOW_DETAIL){ /* We don't print ACK in low detail */
                Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%d > %s:%d %s %s seq=%lu win=%hu (incomplete)",
                   srchost, ntohs(tcp->th_sport), dsthost, ntohs(tcp->th_dport),
                       tflags, ipinfo, (unsigned long) ntohl(tcp->th_seq),
                       ntohs(tcp->th_win));    
            }else if( detail == MEDIUM_DETAIL ){
                Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%d > %s:%d %s seq=%lu ack=%lu win=%hu (incomplete)] IP [%s]",
                   srchost, ntohs(tcp->th_sport), dsthost, ntohs(tcp->th_dport),
                       tflags,  (unsigned long) ntohl(tcp->th_seq),
                       (unsigned long) ntohl(tcp->th_ack),
                       ntohs(tcp->th_win), ipinfo);    
            }else if( detail == HIGH_DETAIL ){
                Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%d > %s:%d %s seq=%lu ack=%lu off=%d res=%d win=%hu (incomplete)] IP [%s]",
                   srchost, ntohs(tcp->th_sport),
                   dsthost, ntohs(tcp->th_dport),
                   tflags, (unsigned long) ntohl(tcp->th_seq),
                   (unsigned long) ntohl(tcp->th_ack),
                   (u8)tcp->th_off, (u8)tcp->th_x2, ntohs(tcp->th_win),
                   ipinfo );
            }

       }
    }
    
    /* CASE 4: where we (finally!) have a full 20 byte TCP header so we can
     * safely print all fields */
    else if (len >= (u32) iphdrlen + 20){
         
      /* TCP Flags */
      p = tflags;
      /* These are basically in tcpdump order */
      if (tcp->th_flags & TH_SYN) *p++ = 'S';
      if (tcp->th_flags & TH_FIN) *p++ = 'F';
      if (tcp->th_flags & TH_RST) *p++ = 'R';
      if (tcp->th_flags & TH_PUSH) *p++ = 'P';
      if (tcp->th_flags & TH_ACK){ *p++ = 'A';
        Snprintf(buf, sizeof(buf), " ack=%lu",
             (unsigned long) ntohl(tcp->th_ack));
        strncat(tcpinfo, buf, sizeof(tcpinfo) - strlen(tcpinfo) - 1);
      }
      if (tcp->th_flags & TH_URG) *p++ = 'U';
      if (tcp->th_flags & TH_ECE) *p++ = 'E'; /* rfc 2481/3168 */
      if (tcp->th_flags & TH_CWR) *p++ = 'C'; /* rfc 2481/3168 */
      *p++ = '\0';


      /* TCP Options */
      if((u32) tcp->th_off * 4 > sizeof(struct tcp_hdr)) {
        if(len < (u32) iphdrlen + (u32) tcp->th_off * 4) {
          Snprintf(tcpoptinfo, sizeof(tcpoptinfo), "option incomplete");

        } else {
          tcppacketoptinfo((u8*) tcp + sizeof(struct tcp_hdr),
                     tcp->th_off*4 - sizeof(struct tcp_hdr),
                     tcpoptinfo, sizeof(tcpoptinfo));
        }
      }

      /* Rest of header fields */
      if( detail == LOW_DETAIL ){
        Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%d > %s:%d %s %s seq=%lu win=%hu %s",
           srchost, ntohs(tcp->th_sport), dsthost, ntohs(tcp->th_dport),
               tflags, ipinfo, (unsigned long) ntohl(tcp->th_seq),
               ntohs(tcp->th_win), tcpoptinfo);               
      }else if( detail == MEDIUM_DETAIL ){
        Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%d > %s:%d %s seq=%lu win=%hu csum=0x%04X%s%s] IP [%s]",
           srchost, ntohs(tcp->th_sport), dsthost, ntohs(tcp->th_dport),
               tflags, (unsigned long) ntohl(tcp->th_seq),
               ntohs(tcp->th_win),  ntohs(tcp->th_sum),
               (tcpoptinfo[0]!='\0') ? " " : "",
               tcpoptinfo, ipinfo );                 
      }else if( detail==HIGH_DETAIL ){
        Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%d > %s:%d %s seq=%lu ack=%lu off=%d res=%d win=%hu csum=0x%04X urp=%d%s%s] IP [%s]",
           srchost, ntohs(tcp->th_sport),
           dsthost, ntohs(tcp->th_dport),
           tflags, (unsigned long) ntohl(tcp->th_seq),
           (unsigned long) ntohl(tcp->th_ack),
           (u8)tcp->th_off, (u8)tcp->th_x2, ntohs(tcp->th_win),
           ntohs(tcp->th_sum), ntohs(tcp->th_urp),
           (tcpoptinfo[0]!='\0') ? " " : "",
           tcpoptinfo, ipinfo );  
      }
    }
    else{
    /* If the packet does not fall into any other category, then we have a
     * really screwed up packet. */ 
        Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? ?? %s (invalid TCP)",
        srchost, dsthost, ipinfo);
    }

    
/* UDP INFORMATION ***********************************************************/
  } else if (nextproto == IPPROTO_UDP && frag_off) {
      Snprintf(protoinfo, sizeof(protoinfo), "UDP %s:?? > %s:?? fragment %s (incomplete)", srchost, dsthost, ipinfo);
  } else if (nextproto == IPPROTO_UDP) {
    udp =  (struct udp_hdr *) (packet + sizeof(struct ip));
  /* TODO: See if we can segfault if we receive a fragmented packet whose IP packet does not say a thing about fragmentation */


  if( detail == LOW_DETAIL ){
    Snprintf(protoinfo, sizeof(protoinfo), "UDP %s:%d > %s:%d %s",
         srchost, ntohs(udp->uh_sport), dsthost, ntohs(udp->uh_dport),
         ipinfo);
  }else if( detail == MEDIUM_DETAIL ){
    Snprintf(protoinfo, sizeof(protoinfo), "UDP [%s:%d > %s:%d csum=0x%04X] IP [%s]",
         srchost, ntohs(udp->uh_sport), dsthost, ntohs(udp->uh_dport), ntohs(udp->uh_sum),
         ipinfo);
  }else if( detail==HIGH_DETAIL ){
    Snprintf(protoinfo, sizeof(protoinfo), "UDP [%s:%d > %s:%d len=%d csum=0x%04X] IP [%s]",
         srchost, ntohs(udp->uh_sport), dsthost, ntohs(udp->uh_dport),
         ntohs(udp->uh_ulen), ntohs(udp->uh_sum),
         ipinfo);
  }


/* SCTP INFORMATION **********************************************************/
  } else if (nextproto == IPPROTO_SCTP && frag_off) {
      Snprintf(protoinfo, sizeof(protoinfo), "SCTP %s:?? > %s:?? fragment %s (incomplete)", srchost, dsthost, ipinfo);
  } else if (nextproto == IPPROTO_SCTP) {
    sctp =  (struct sctp_hdr *) (packet + sizeof(struct ip));

    if( detail == LOW_DETAIL ){
        Snprintf(protoinfo, sizeof(protoinfo), "SCTP %s:%d > %s:%d %s",
             srchost, ntohs(sctp->sh_sport), dsthost, ntohs(sctp->sh_dport),
             ipinfo);
    }else if( detail == MEDIUM_DETAIL ){
        Snprintf(protoinfo, sizeof(protoinfo), "SCTP [%s:%d > %s:%d csum=0x%04x] IP [%s]",
             srchost, ntohs(sctp->sh_sport), dsthost, ntohs(sctp->sh_dport), ntohl(sctp->sh_sum),
             ipinfo);
    }else if( detail==HIGH_DETAIL ){
        Snprintf(protoinfo, sizeof(protoinfo), "SCTP [%s:%d > %s:%d vtag=%ul csum=0x%08x] IP [%s]",
             srchost, ntohs(sctp->sh_sport), dsthost, ntohs(sctp->sh_dport),
             ntohl(sctp->sh_sum), ntohl(sctp->sh_vtag),
             ipinfo);
    }


/* ICMP INFORMATION **********************************************************/
  } else if (nextproto == IPPROTO_ICMP && frag_off) {
      Snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s fragment %s (incomplete)", srchost, dsthost, ipinfo);
  } else if (nextproto == IPPROTO_ICMP) {

    struct ip *ip2;       /* Points to the IP datagram carried by some ICMP messages */
    char *ip2dst;         /* Dest IP in caried IP datagram                   */
    u16 *nextmtu=NULL;    /* Store next hop MTU when ICMP==Frag required     */
    char auxbuff[128];    /* Aux buffer                                      */
    struct icmp_packet{   /* Generic ICMP struct */
      u8 type;
      u8 code;
      u16 checksum;
      u8 data[128];
    }*icmppkt;    
    struct ppkt {         /* Beginning of ICMP Echo/Timestamp header         */
      u8 type;
      u8 code;
      u16 checksum;
      u16 id;
      u16 seq;
    } *ping = NULL;
    struct icmp_redir{
      u8 type;
      u8 code;
      u16 checksum;
      u32 addr;
    } *icmpredir=NULL;
    struct icmp_router{
      u8 type;
      u8 code;
      u16 checksum;
      u8 addrs;
      u8 addrlen;
      u16 lifetime;
    } *icmprouter=NULL;
    struct icmp_param{
      u8 type;
      u8 code;
      u16 checksum;
      u8 pnt;
      u8 unused;
      u16 unused2;
    } *icmpparam=NULL;
    struct icmp_tstamp{
      u8 type;
      u8 code;
      u16 checksum;
      u16 id;
      u16 seq;
      u32 orig;
      u32 recv;
      u32 trans;
    } *icmptstamp=NULL;
    struct icmp_mask{
      u8 type;
      u8 code;
      u16 checksum;
      u16 id;
      u16 seq;
      u32 mask;
    } *icmpmask=NULL;
    
    /* Compute the length of the IP datagram + ICMP minimum length  */
    unsigned pktlen = (iphdrlen) + 8;

    /* We need the ICMP packet to be at least 8 bytes long */
    if (pktlen > len)
      goto icmpbad;
      
    ping = (struct ppkt *) ((iphdrlen) + (char *) ip);
    icmppkt=(struct icmp_packet *)  ((iphdrlen) + (char *) ip);
    
    switch(icmppkt->type) {

        /* Echo Reply **************************/
        case 0: 
          strcpy(icmptype, "Echo reply");
          Snprintf(icmpfields, sizeof(icmpfields), "id=%u seq=%u", ntohs(ping->id), ntohs(ping->seq) );
        break;

        /* Destination Unreachable *************/
        case 3: 
            /* Point to the start of the original datagram */
            ip2 = (struct ip *) ((char *) ip + (iphdrlen) + 8);
                
            /* Check we have a full IP datagram included in the ICMP message */
            pktlen += MAX( (ip2->ip_hl * 4), 20 );
            if (pktlen > len){
                if(len==(u32)(iphdrlen) + 8 )
                    Snprintf(icmptype, sizeof icmptype, "Destination unreachable%s",
                    (detail!=LOW_DETAIL)? " (original datagram missing)" : "" );
                else
                    Snprintf(icmptype, sizeof icmptype, "Destination unreachable%s",
                    (detail!=LOW_DETAIL)? " (part of original datagram missing)" : "" );
                goto icmpbad;
            }

            /* Basic check to ensure we have an IPv4 datagram attached */
            /* TODO: We should actually check the datagram checksum to
             * see if it validates becuase just checking the version number
             * is not enough. On average, if we get random data 1 out of
             * 16 (2^4bits) times we will have value 4. */
            if( (ip2->ip_v != (u8)4) || ((ip2->ip_hl * 4)<20) || ((ip2->ip_hl * 4)>60) ){
                Snprintf(icmptype, sizeof icmptype, "Destination unreachable (bogus original datagram)");                         
                goto icmpbad;
            }else
            
            /* We have the original datagram + the first 8 bytes of the
             * transport layer header */    
            if ( (pktlen+8) < len) {
                tcp = (struct tcp_hdr *) ((char *) ip2 + (ip2->ip_hl * 4));
                udp = (struct udp_hdr *) ((char *) ip2 + (ip2->ip_hl * 4));
                sctp = (struct sctp_hdr *) ((char *) ip2 + (ip2->ip_hl * 4));
            }
            
            /* Determine the IP the original datagram was sent to */
            ip2dst = inet_ntoa(ip2->ip_dst);

            /* Determine type of Destination unreachable from the code value */
            switch (icmppkt->code) {
                case 0:
                    Snprintf(icmptype, sizeof icmptype, "Network %s unreachable", ip2dst);
                break;

                case 1:
                    Snprintf(icmptype, sizeof icmptype, "Host %s unreachable", ip2dst);
                break;

                case 2:
                    Snprintf(icmptype, sizeof icmptype, "Protocol %u unreachable", ip2->ip_p);
                break;

                case 3:
                    if ( (pktlen+8) < len){
                        if (ip2->ip_p == IPPROTO_UDP && udp)
                          Snprintf(icmptype, sizeof icmptype, "Port %u unreachable", ntohs(udp->uh_dport));
                        else if (ip2->ip_p == IPPROTO_TCP && tcp)
                          Snprintf(icmptype, sizeof icmptype, "Port %u unreachable", ntohs(tcp->th_dport));
                        else if (ip2->ip_p == IPPROTO_SCTP && sctp)
                          Snprintf(icmptype, sizeof icmptype, "Port %u unreachable", ntohs(sctp->sh_dport));
                        else
                          Snprintf(icmptype, sizeof icmptype, "Port unreachable (unknown protocol %u)", ip2->ip_p);
                    }
                    else
                        strcpy(icmptype, "Port unreachable");
                break;

                case 4:
                    strcpy(icmptype, "Fragmentation required");
                    nextmtu = (u16 *)(&(icmppkt->data[6]));
                    Snprintf(icmpfields, sizeof(icmpfields), "Next-Hop-MTU=%u", ntohs(*nextmtu) );
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
          if (ping->code == 0)
            strcpy(icmptype, "Network redirect");
          else if (ping->code == 1)
            strcpy(icmptype, "Host redirect");
          else strcpy(icmptype, "Redirect (unknown code)");
          icmpredir=(struct icmp_redir *)icmppkt;
          inet_ntop(AF_INET, &icmpredir->addr, auxbuff, sizeof(auxbuff) );
          Snprintf(icmpfields, sizeof(icmpfields), "addr=%s", auxbuff);                
        break;

        /* Echo Request ************************/        
        case 8:
          strcpy(icmptype, "Echo request");
          Snprintf(icmpfields, sizeof(icmpfields), "id=%u seq=%u", ntohs(ping->id), ntohs(ping->seq) );
        break;
        
        /* Router Advertisement ****************/
        case 9:
            if(icmppkt->code==16)
                strcpy(icmptype, "Router advertisement (Mobile Agent Only)");
            else
                strcpy(icmptype, "Router advertisement");
            icmprouter=(struct icmp_router *)icmppkt;          
            Snprintf(icmpfields, sizeof(icmpfields), "addrs=%u addrlen=%u lifetime=%d",
                icmprouter->addrs,
                icmprouter->addrlen,
                ntohs(icmprouter->lifetime) );
        break;

        /* Router Solicitation *****************/
        case 10:
          strcpy(icmptype, "Router solicitation");
        break;

        /* Time Exceeded ***********************/        
        case 11:
          if (icmppkt->code == 0)
            strcpy(icmptype, "TTL=0 during transit");
          else if (icmppkt->code == 1)
            strcpy(icmptype, "TTL=0 during reassembly");
          else strcpy(icmptype, "TTL exceeded (unknown code)");
        break;

        /* Parameter Problem *******************/        
        case 12:
          if (ping->code == 0)
            strcpy(icmptype, "Parameter problem (pointer indicates error)");
          else if (ping->code == 1)
            strcpy(icmptype, "Parameter problem (option missing)");
          else if (ping->code == 2)
            strcpy(icmptype, "Parameter problem (bad length)");
          else
            strcpy(icmptype, "Parameter problem (unknown code)");
          icmpparam=(struct icmp_param *)icmppkt;
          Snprintf(icmpfields, sizeof(icmpfields), "pointer=%d", icmpparam->pnt);            
        break;

        /* Timestamp Request/Reply *************/
        case 13:
        case 14:
          Snprintf(icmptype, sizeof(icmptype), "Timestamp %s", (icmppkt->type==13)? "request" : "reply" );
          icmptstamp=(struct icmp_tstamp *)icmppkt;
          Snprintf(icmpfields, sizeof(icmpfields), "id=%u seq=%u orig=%lu recv=%lu trans=%lu",
            ntohs(icmptstamp->id), ntohs(icmptstamp->seq),
            (unsigned long)ntohl(icmptstamp->orig),
            (unsigned long)ntohl(icmptstamp->recv),
            (unsigned long)ntohl(icmptstamp->trans) );     
        break;

        /* Information Request *****************/
        case 15:
          strcpy(icmptype, "Information request");
          Snprintf(icmpfields, sizeof(icmpfields), "id=%u seq=%u", ntohs(ping->id), ntohs(ping->seq) );
        break;

        /* Information Reply *******************/        
        case 16:
          strcpy(icmptype, "Information reply");
          Snprintf(icmpfields, sizeof(icmpfields), "id=%u seq=%u", ntohs(ping->id), ntohs(ping->seq) );
        break;

        /* Netmask Request/Reply ***************/ 
        case 17:
        case 18:
          Snprintf(icmptype, sizeof(icmptype), "Address mask %s", (icmppkt->type==17)? "request" : "reply" );
          icmpmask=(struct icmp_mask *)icmppkt;
          inet_ntop(AF_INET, &icmpmask->mask, auxbuff, sizeof(auxbuff) );
          Snprintf(icmpfields, sizeof(icmpfields), "id=%u seq=%u mask=%s",
            ntohs(ping->id), ntohs(ping->seq), auxbuff); 
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

    
    if (pktlen > len) {
    icmpbad:
      if (ping) {
        /* We still have this information */
        Snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s %s (type=%d/code=%d) %s",
         srchost, dsthost, icmptype, ping->type, ping->code, ipinfo);
      } else {
        Snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s [??] %s",
         srchost, dsthost, ipinfo);
      }
    } else {
            if(ping)
                sprintf(icmpinfo,"type=%d/code=%d", ping->type, ping->code);
            else
                strncpy(icmpinfo,"type=?/code=?", sizeof(icmpinfo) );        

        if( detail==LOW_DETAIL ){           
            Snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s %s (%s) %s",
                srchost, dsthost, icmptype, icmpinfo, ipinfo);
        }else{
            Snprintf(protoinfo, sizeof(protoinfo), "ICMP [%s > %s %s (%s) %s] IP [%s]",
                srchost, dsthost, icmptype, icmpinfo, icmpfields, ipinfo);
        }
     
    }

/* UNKNOWN PROTOCOL **********************************************************/
  } else if( nextproto == IPPROTO_ICMPV6){
        Snprintf(protoinfo, sizeof(protoinfo), "ICMPv6 (%d) %s > %s: %s",
            ip->ip_p, srchost, dsthost, ipinfo);
  }else{

    if( nexthdrtoa(nextproto, 1) == NULL ){
        Snprintf(protoinfo, sizeof(protoinfo), "Unknown protocol (%d) %s > %s: %s",
            ip->ip_p, srchost, dsthost, ipinfo);
    }else{
           Snprintf(protoinfo, sizeof(protoinfo), "%s (%d) %s > %s: %s",
            nexthdrtoa(nextproto, 1), ip->ip_p, srchost, dsthost, ipinfo); 
    }
  }

  return protoinfo;
}


static int match_netmask(u32 addr1, u32 addr2, u32 mask) {
  return (addr1 & mask) == (addr2 & mask);
}

static int match_netmask_bits(u32 addr1, u32 addr2, int bits) {
  return match_netmask(addr1, addr2, htonl((unsigned long) (0 - 1) << (32 - bits)));
}

static int match_netmask_bits(const struct sockaddr_in *addr1,
  const struct sockaddr_in *addr2, int bits) {
  return match_netmask_bits(addr1->sin_addr.s_addr, addr2->sin_addr.s_addr, bits);
}

static struct interface_info *find_loopback_iface(struct interface_info *ifaces,
  int numifaces) {
  int i;

  for (i = 0; i < numifaces; i++) {
    if (ifaces[i].device_type == devt_loopback)
      return &ifaces[i];
  }

  return NULL;
}

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
              char *device, struct sockaddr_storage *spoofss) {
  struct interface_info *ifaces;
  struct interface_info *iface;
  int numifaces = 0;
  struct sys_route *routes;
  int numroutes = 0;
  int i;
  struct sockaddr_in *ifsin, *dstsin;
  char errstr[256];
  errstr[0]='\0';

  if (!dst)
    netutil_fatal("%s passed a NULL dst address", __func__);
  dstsin = (struct sockaddr_in *) dst;

  if (dstsin->sin_family != AF_INET)
    netutil_fatal("Sorry -- %s currently only supports IPv4", __func__);

  if(spoofss!=NULL){
    /* Throughout the rest of this function we only change rnfo->srcaddr if the source isnt spoofed */
    memcpy(&rnfo->srcaddr, spoofss, sizeof(rnfo->srcaddr));
    /* The device corresponding to this spoofed address should already have been set elsewhere. */
    assert(device!=NULL && device[0]!='\0');
  }

  if (device!=NULL && device[0]!='\0'){
    iface = getInterfaceByName(device);
    if (!iface)
      netutil_fatal("Could not find interface %s which was specified by -e", device);
  } else {
    iface = NULL;
  }

  if((routes=getsysroutes(&numroutes, errstr, sizeof(errstr)))==NULL)
    netutil_fatal("%s: Failed to obtain system routes: %s", __func__, errstr);
  if((ifaces=getinterfaces(&numifaces, errstr, sizeof(errstr)))==NULL)
    netutil_fatal("%s: Failed to obtain system interfaces: %s", __func__, errstr);

  /* First check if dst is one of the localhost's own addresses. We need to use
     a localhost device for these. */
  for (i = 0; i < numifaces; i++) {
    struct interface_info *loopback;

    ifsin = (struct sockaddr_in *) &ifaces[i].addr;
    if (dstsin->sin_addr.s_addr != ifsin->sin_addr.s_addr)
      continue;
    if (iface != NULL && strcmp(ifaces[i].devname, iface->devname) != 0)
      continue;

    if (ifaces[i].device_type == devt_loopback)
      loopback = &ifaces[i];
    else
      loopback = find_loopback_iface(ifaces, numifaces);
    if (loopback == NULL)
      /* Hmmm ... no localhost -- move on to the routing table. */
      break;

    rnfo->ii = *loopback;
    rnfo->direct_connect = 1;
    /* But the source address we want to use is the target address. */
    if (!spoofss)
      rnfo->srcaddr = ifaces[i].addr;

    return 1;
  }

  /* Go through the routing table and take the first match. getsysroutes sorts
     so more-specific routes come first. */
  for (i = 0; i < numroutes; i++) {
    if (!match_netmask(dstsin->sin_addr.s_addr, routes[i].dest, routes[i].netmask))
      continue;
    /* Ignore routes that aren't on the device we specified. */
    if (iface != NULL && strcmp(routes[i].device->devname, iface->devname) != 0)
      continue;

    rnfo->ii = *routes[i].device;
    /* At this point we don't whether this route is direct or indirect ("G" flag
       in netstat). We guess that a route is direct when the gateway address is
       0.0.0.0, when it exactly matches the interface address, or when it
       exactly matches the destination address. */
    rnfo->direct_connect = (routes[i].gw.s_addr == 0) ||
      (routes[i].gw.s_addr == ((struct sockaddr_in *) &routes[i].device->addr)->sin_addr.s_addr) ||
      (routes[i].gw.s_addr == dstsin->sin_addr.s_addr);
    if (!spoofss)
      rnfo->srcaddr = routes[i].device->addr;
    ifsin = (struct sockaddr_in *) &rnfo->nexthop;
    ifsin->sin_family = AF_INET;
    ifsin->sin_addr = routes[i].gw;

    return 1;
  }

  /* No match on routes. Try interfaces directly. */
  for (i = 0; i < numifaces; i++) {
    if (ifaces[i].addr.ss_family != AF_INET)
      continue;
    ifsin = (struct sockaddr_in *) &ifaces[i].addr;
    if (!match_netmask_bits(dstsin, ifsin, ifaces[i].netmask_bits))
      continue;
    if (iface != NULL && strcmp(ifaces[i].devname, iface->devname) != 0)
      continue;

    rnfo->ii = ifaces[i];
    rnfo->direct_connect = 1;
    if (!spoofss)
      rnfo->srcaddr = ifaces[i].addr;

    return 1;
  }

  return 0;
}

/* Wrapper for system function sendto(), which retries a few times when
 * the call fails. It also prints informational messages about the
 * errors encountered. It returns the number of bytes sent or -1 in
 * case of error. */
int Sendto(const char *functionname, int sd, 
                  const unsigned char *packet, int len, unsigned int flags,
                  struct sockaddr *to, int tolen) {

  struct sockaddr_in *sin = (struct sockaddr_in *) to;
  int res;
  int retries = 0;
  int sleeptime = 0;
  static int numerrors = 0;

  do {
    if ((res = sendto(sd, (const char *) packet, len, flags, to, tolen)) == -1) {
      int err = socket_errno();

      numerrors++;
        if(numerrors <= 10) {
        netutil_error("sendto in %s: sendto(%d, packet, %d, 0, %s, %d) => %s",
              functionname, sd, len, inet_ntoa(sin->sin_addr), tolen,
              strerror(err));
        netutil_error("Offending packet: %s", ippackethdrinfo(packet, len, LOW_DETAIL));
        if (numerrors == 10) {
          netutil_error("Omitting future %s error messages now that %d have been shown.  Use -d2 if you really want to see them.", __func__, numerrors);
        }
      }
#if WIN32
      return -1;
#else
      if (retries > 2 || err == EPERM || err == EACCES || err == EMSGSIZE
          || err == EADDRNOTAVAIL || err == EINVAL)
        return -1;
      sleeptime = 15 * (1 << (2 * retries));
      netutil_error("Sleeping %d seconds then retrying", sleeptime);
      fflush(stderr);
      sleep(sleeptime);
#endif
    }
    retries++;
  } while (res == -1);

  return res;
}



/* Send an IP packet over an ethernet handle. */
int send_ip_packet_eth(struct eth_nfo *eth, u8 *packet, unsigned int packetlen) {
  eth_t *ethsd;
  u8 *eth_frame;
  int res;

  eth_frame = (u8 *) safe_malloc(14 + packetlen);
  memcpy(eth_frame + 14, packet, packetlen);
  eth_pack_hdr(eth_frame, eth->dstmac, eth->srcmac, ETH_TYPE_IP);
  if (!eth->ethsd) {
    ethsd = eth_open_cached(eth->devname);
    if (!ethsd)
      netutil_fatal("%s: Failed to open ethernet device (%s)", __func__, eth->devname);
  } else {
    ethsd = eth->ethsd;
  }
  res = eth_send(ethsd, eth_frame, 14 + packetlen);
  /* No need to close ethsd due to caching */
  free(eth_frame);

  return res;
}


/* Send an IP packet over a raw socket. */
int send_ip_packet_sd(int sd, u8 *packet, unsigned int packetlen) {
  struct sockaddr_in sock;
  struct ip *ip = (struct ip *) packet;
  struct tcp_hdr *tcp;
  struct udp_hdr *udp;
  int res;

  assert(sd >= 0);
  memset(&sock, 0, sizeof(sock));
  sock.sin_family = AF_INET;
#if HAVE_SOCKADDR_SA_LEN
  sock.sin_len = sizeof(sock);
#endif

  /* It is bogus that I need the address and port info when sending a RAW IP 
     packet, but it doesn't seem to work w/o them */
  if (packetlen >= 20) {
    sock.sin_addr.s_addr = ip->ip_dst.s_addr;
    if (ip->ip_p == IPPROTO_TCP
        && packetlen >= (unsigned int) ip->ip_hl * 4 + 20) {
      tcp = (struct tcp_hdr *) ((u8 *) ip + ip->ip_hl * 4);
      sock.sin_port = tcp->th_dport;
    } else if (ip->ip_p == IPPROTO_UDP
               && packetlen >= (unsigned int) ip->ip_hl * 4 + 8) {
      udp = (struct udp_hdr *) ((u8 *) ip + ip->ip_hl * 4);
      sock.sin_port = udp->uh_dport;
    }
  }

  /* Equally bogus is that the IP total len and IP fragment offset
     fields need to be in host byte order on certain BSD variants.  I
     must deal with it here rather than when building the packet,
     because they should be in NBO when I'm sending over raw
     ethernet */
#if FREEBSD || BSDI || NETBSD || DEC || MACOSX
  ip->ip_len = ntohs(ip->ip_len);
  ip->ip_off = ntohs(ip->ip_off);
#endif

  res = Sendto("send_ip_packet_sd", sd, packet, packetlen, 0,
               (struct sockaddr *) &sock,
               (int) sizeof(struct sockaddr_in));

  /* Undo the byte order switching. */
#if FREEBSD || BSDI || NETBSD || DEC || MACOSX
  ip->ip_len = htons(ip->ip_len);
  ip->ip_off = htons(ip->ip_off);
#endif

  return res;
}



/* Sends the supplied pre-built IPv4 packet. The packet is sent through
 * the raw socket "sd" if "eth" is NULL. Otherwise, it gets sent at raw
 * ethernet level. */
int send_ip_packet_eth_or_sd(int sd, struct eth_nfo *eth, u8 *packet, unsigned int packetlen){
  if(eth)
    return send_ip_packet_eth(eth, packet, packetlen);
  else
    return send_ip_packet_sd(sd, packet, packetlen);
}



/* Create and send all fragments of a pre-built IPv4 packet
 * Minimal MTU for IPv4 is 68 and maximal IPv4 header size is 60
 * which gives us a right to cut TCP header after 8th byte
 * (shouldn't we inflate the header to 60 bytes too?) */
int send_frag_ip_packet(int sd, struct eth_nfo *eth, u8 *packet,
                        unsigned int packetlen, u32 mtu) {
  struct ip *ip = (struct ip *) packet;
  int headerlen = ip->ip_hl * 4; // better than sizeof(struct ip)
  u32 datalen = packetlen - headerlen;
  int fdatalen = 0, res = 0;
  int fragment=0;

  assert(headerlen <= (int) packetlen);
  assert(headerlen >= 20 && headerlen <= 60); // sanity check (RFC791)
  assert(mtu > 0 && mtu % 8 == 0); // otherwise, we couldn't set Fragment offset (ip->ip_off) correctly

  if (datalen <= mtu) {
    netutil_error("Warning: fragmentation (mtu=%lu) requested but the payload is too small already (%lu)", (unsigned long)mtu, (unsigned long)datalen);
    return send_ip_packet_eth_or_sd(sd, eth, packet, packetlen);
  }

  u8 *fpacket = (u8 *) safe_malloc(headerlen + mtu);
  memcpy(fpacket, packet, headerlen + mtu);
  ip = (struct ip *) fpacket;

  // create fragments and send them
  for (fragment = 1; fragment * mtu < datalen + mtu; fragment++) {
    fdatalen = (fragment * mtu <= datalen ? mtu : datalen % mtu);
    ip->ip_len = htons(headerlen + fdatalen);
    ip->ip_off = htons((fragment - 1) * mtu / 8);
    if ((fragment - 1) * mtu + fdatalen < datalen)
      ip->ip_off |= htons(IP_MF);
#if HAVE_IP_IP_SUM
    ip->ip_sum = 0;
    ip->ip_sum = in_cksum((unsigned short *) ip, headerlen);
#endif
    if (fragment > 1) // copy data payload
      memcpy(fpacket + headerlen,
             packet + headerlen + (fragment - 1) * mtu, fdatalen);
    res = send_ip_packet_eth_or_sd(sd, eth, fpacket, ntohs(ip->ip_len));
    if (res == -1)
      break;
  }
  free(fpacket);
  return res;
}



#ifdef WIN32
/* Convert a dnet interface name into the long pcap style.  This also caches the
   data to speed things up.  Fills out pcapdev (up to pcapdevlen) and returns
   true if it finds anything. Otherwise returns false.  This is only necessary
   on Windows. */
int DnetName2PcapName(const char *dnetdev, char *pcapdev, int pcapdevlen) {
  static struct NameCorrelationCache {
    char dnetd[64];
    char pcapd[128];
  } *NCC = NULL;
  static int NCCsz = 0;
  static int NCCcapacity = 0;
  int i;
  char tmpdev[128];

  // Init the cache if not done yet
  if (!NCC) {
    NCCcapacity = 5;
    NCC =
        (struct NameCorrelationCache *) safe_zalloc(NCCcapacity *
                                                    sizeof(*NCC));
    NCCsz = 0;
  }
  // First check if the name is already in the cache
  for (i = 0; i < NCCsz; i++) {
    if (strcmp(NCC[i].dnetd, dnetdev) == 0) {
      Strncpy(pcapdev, NCC[i].pcapd, pcapdevlen);
      return 1;
    }
  }

  // OK, so it isn't in the cache.  Let's ask dnet for it.
/* Converts a dnet interface name (ifname) to its pcap equivalent, which is stored in
pcapdev (up to a length of pcapdevlen).  Returns 0 and fills in pcapdev if successful. */
  if (eth_get_pcap_devname(dnetdev, tmpdev, sizeof(tmpdev)) != 0)
    return 0;

  // We've got it.  Let's add it to the cache
  if (NCCsz >= NCCcapacity) {
    NCCcapacity <<= 2;
    NCC =
        (struct NameCorrelationCache *) safe_realloc(NCC,
                                                     NCCcapacity *
                                                     sizeof(*NCC));
  }
  Strncpy(NCC[NCCsz].dnetd, dnetdev, sizeof(NCC[0].dnetd));
  Strncpy(NCC[NCCsz].pcapd, tmpdev, sizeof(NCC[0].pcapd));
  NCCsz++;
  Strncpy(pcapdev, tmpdev, pcapdevlen);
  return 1;
}
#endif


/* Compute exponential sleep time for my_pcap_open_live(). Returned
 * value is 5 to the times-th power (5^times) */
static unsigned int compute_sleep_time(unsigned int times){
    unsigned int i=0;
    unsigned int result=1;
    for(i=0; i<times; i++)
        result*=5;
    return result;
}

/* This function is  used to obtain a packet capture handle to look at
 * packets on the network. It is actually a wrapper for libpcap's
 * pcap_open_live() that takes care of compatibility issues and error
 * checking. The function attempts to open the device up to three times.
 * If the call does not succeed the third time, NULL is returned. */
pcap_t *my_pcap_open_live(const char *device, int snaplen, int promisc, int to_ms){
  char err0r[PCAP_ERRBUF_SIZE];
  pcap_t *pt;
  char pcapdev[128];
  unsigned int failed = 0;

  assert(device != NULL);

#ifdef WIN32
  /* Nmap normally uses device names obtained through dnet for interfaces, but
     Pcap has its own naming system.  So the conversion is done here */
  if (!DnetName2PcapName(device, pcapdev, sizeof(pcapdev))) {
    /* Oh crap -- couldn't find the corresponding dev apparently.  Let's just go
       with what we have then ... */
    Strncpy(pcapdev, device, sizeof(pcapdev));
  }
#else
  Strncpy(pcapdev, device, sizeof(pcapdev));
#endif
  do {
    pt = pcap_open_live(pcapdev, snaplen, promisc, to_ms, err0r);
    if (!pt) {
      failed++;
      if (failed >= 3) {
          return NULL;
      } else {
        netutil_error("pcap_open_live(%s, %d, %d, %d) FAILED. Reported error: %s.  Will wait %d seconds then retry.", pcapdev, snaplen, promisc, to_ms, err0r, compute_sleep_time(failed));
      }
      sleep( compute_sleep_time(failed) );
    }
  } while (!pt);

#ifdef WIN32
  /* We want any responses back ASAP */
  pcap_setmintocopy(pt, 1);
#endif

  return pt;
}


/* Set a pcap filter */
void set_pcap_filter(const char *device, pcap_t *pd, const char *bpf, ...) {
  va_list ap;
  char buf[3072];
  struct bpf_program fcode;
#ifndef __amigaos__
  unsigned int localnet, netmask;
#else
  bpf_u_int32 localnet, netmask;
#endif
  char err0r[256];

  // Cast below is becaue OpenBSD apparently has a version that takes a
  // non-const device (hopefully they don't actually write to it).
  if (pcap_lookupnet((char *) device, &localnet, &netmask, err0r) < 0)
    netutil_fatal("Failed to lookup subnet/netmask for device (%s): %s", device, err0r);

  va_start(ap, bpf);
  if (Vsnprintf(buf, sizeof(buf), bpf, ap) >= (int) sizeof(buf))
    netutil_fatal("%s called with too-large filter arg\n", __func__);
  va_end(ap);

  /* Due to apparent bug in libpcap */
  /* Maybe this bug no longer exists ... I'll comment out for now 
   *      if (islocalhost(target->v4hostip()))
   *      buf[0] = '\0'; */

  if (pcap_compile(pd, &fcode, buf, 0, netmask) < 0)
    netutil_fatal("Error compiling our pcap filter: %s", pcap_geterr(pd));
  if (pcap_setfilter(pd, &fcode) < 0)
    netutil_fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));
  pcap_freecode(&fcode);
}


/* Returns true if the captured frame is ARP. This function understands the
   datalink types DLT_EN10MB and DLT_LINUX_SLL. */
static bool frame_is_arp(const u8 *frame, int datalink) {
  if (datalink == DLT_EN10MB) {
    return ntohs(*((u16 *) (frame + 12))) == ETH_TYPE_ARP;
  } else if (datalink == DLT_LINUX_SLL) {
    return ntohs(*((u16 *) (frame + 2))) == ARPHRD_ETHER && /* sll_hatype */
      ntohs(*((u16 *) (frame + 4))) == 6 && /* sll_halen */
      ntohs(*((u16 *) (frame + 14))) == ETH_TYPE_ARP; /* sll_protocol */
  } else {
    return false;
  }
}

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
                        void (*traceArp_callback)(int, const u8 *, u32 , struct timeval *)) {
  static int warning = 0;
  int datalink;
  struct pcap_pkthdr head;
  u8 *p;
  int timedout = 0;
  int badcounter = 0;
  unsigned int offset=0;
  struct timeval tv_start, tv_end;

  if (!pd)
    netutil_fatal("NULL packet device passed to %s", __func__);

  if (to_usec < 0) {
    if (!warning) {
      warning = 1;
      netutil_error("WARNING: Negative timeout value (%lu) passed to %s() -- using 0", to_usec, __func__);
    }
    to_usec = 0;
  }

  /* New packet capture device, need to recompute offset */
  if ((datalink = pcap_datalink(pd)) < 0)
    netutil_fatal("Cannot obtain datalink information: %s", pcap_geterr(pd));

  if (datalink == DLT_EN10MB) {
    offset = ETH_HDR_LEN;
  } else if (datalink == DLT_LINUX_SLL) {
    /* The datalink type is Linux "cooked" sockets. See pcap-linktype(7). */
    offset = 16;
  } else {
    netutil_fatal("%s called on interface that is datatype %d rather than DLT_EN10MB (%d) or DLT_LINUX_SLL (%d)", __func__, datalink, DLT_EN10MB, DLT_LINUX_SLL);
  }

  if (to_usec > 0) {
    gettimeofday(&tv_start, NULL);
  }

  do {
#ifdef WIN32
    if (to_usec == 0) {
      PacketSetReadTimeout(pd->adapter, 1);
    } else {
      gettimeofday(&tv_end, NULL);
      long to_left =
          MAX(1, (to_usec - TIMEVAL_SUBTRACT(tv_end, tv_start)) / 1000);
      // Set the timeout (BUGBUG: this is cheating)
      PacketSetReadTimeout(pd->adapter, to_left);
    }
#endif

    p = NULL;

    if (pcap_select(pd, to_usec) == 0)
      timedout = 1;
    else
      p = (u8 *) pcap_next(pd, &head);

    if (p && head.caplen >= offset + 28) {
      /* hw type eth (0x0001), prot ip (0x0800),
         hw size (0x06), prot size (0x04) */
      if (frame_is_arp(p, datalink) &&
        memcmp(p + offset, "\x00\x01\x08\x00\x06\x04\x00\x02", 8) == 0) {
        memcpy(sendermac, p + offset + 8, 6);
        /* I think alignment should allow this ... */
        memcpy(&senderIP->s_addr, p + offset + 14, 4);
        break;
      }
    }

    if (!p) {
      /* Should we timeout? */
      if (to_usec == 0) {
        timedout = 1;
      } else if (to_usec > 0) {
        gettimeofday(&tv_end, NULL);
        if (TIMEVAL_SUBTRACT(tv_end, tv_start) >= to_usec) {
          timedout = 1;
        }
      }
    } else {
      /* We'll be a bit patient if we're getting actual packets back, but
         not indefinitely so */
      if (badcounter++ > 50)
        timedout = 1;
    }
  } while (!timedout);

  if (timedout)
    return 0;

  if (rcvdtime) {
    // FIXME: I eventually need to figure out why Windows head.ts time is sometimes BEFORE the time I
    // sent the packet (which is according to gettimeofday() in nbase).  For now, I will sadly have to
    // use gettimeofday() for Windows in this case
    // Actually I now allow .05 discrepancy.   So maybe this isn't needed.  I'll comment out for now.
    // Nope: it is still needed at least for Windows.  Sometimes the time from he pcap header is a 
    // COUPLE SECONDS before the gettimeofday() results :(.
#if defined(WIN32) || defined(__amigaos__)
    gettimeofday(&tv_end, NULL);
    *rcvdtime = tv_end;
#else
    rcvdtime->tv_sec = head.ts.tv_sec;
    rcvdtime->tv_usec = head.ts.tv_usec;
    assert(head.ts.tv_sec);
#endif
  }
  if(traceArp_callback!=NULL){
    /* TODO: First parameter "2" is a hardcoded value for Nmap's PacketTrace::RECV*/
    traceArp_callback(2, (u8 *) p + offset, ARP_HDR_LEN + ARP_ETHIP_LEN, rcvdtime);
  }

  return 1;
}

/* Issues an ARP request for the MAC of targetss (which will be placed
   in targetmac if obtained) from the source IP (srcip) and source mac
   (srcmac) given.  "The request is ussued using device dev to the
   broadcast MAC address.  The transmission is attempted up to 3
   times.  If none of these elicit a response, false will be returned.
   If the mac is determined, true is returned. The last parameter is
   a pointer to a callback function that can be used for packet tracing.
   This is intended to be used by Nmap only. Any other calling this
   should pass NULL instead. */
bool doArp(const char *dev, const u8 *srcmac,
                  const struct sockaddr_storage *srcip,
                  const struct sockaddr_storage *targetip,
                  u8 *targetmac,
                  void (*traceArp_callback)(int, const u8 *, u32 , struct timeval *)
                  ) {
  /* timeouts in microseconds ... the first ones are retransmit times, while 
     the final one is when we give up */
  int timeouts[] = { 100000, 400000, 800000 };
  int max_sends = 3;
  int num_sends = 0; // How many we have sent so far 
  eth_t *ethsd;
  u8 frame[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];
  const struct sockaddr_in *targetsin = (struct sockaddr_in *) targetip;
  const struct sockaddr_in *srcsin = (struct sockaddr_in *) srcip;
  struct timeval start, now, rcvdtime;
  int timeleft;
  int listenrounds;
  int rc;
  pcap_t *pd;
  struct in_addr rcvdIP;
  bool foundit = false;
  char filterstr[256];

  if (targetsin->sin_family != AF_INET || srcsin->sin_family != AF_INET)
    netutil_fatal("%s can only handle IPv4 addresses", __func__);

  /* Start listening */
  if((pd=my_pcap_open_live(dev, 50, 1, 25))==NULL)
    netutil_fatal("my_pcap_open_live(%s, 50, 1, 25) failed three times.", dev);
  Snprintf(filterstr, 256, "arp and arp[18:4] = 0x%02X%02X%02X%02X and arp[22:2] = 0x%02X%02X",
           srcmac[0], srcmac[1], srcmac[2], srcmac[3], srcmac[4], srcmac[5]);
  set_pcap_filter(dev, pd, filterstr);

  /* Prepare probe and sending stuff */
  ethsd = eth_open_cached(dev);
  if (!ethsd)
    netutil_fatal("%s: failed to open device %s", __func__, dev);
  eth_pack_hdr(frame, ETH_ADDR_BROADCAST, *srcmac, ETH_TYPE_ARP);
  arp_pack_hdr_ethip(frame + ETH_HDR_LEN, ARP_OP_REQUEST, *srcmac,
                     srcsin->sin_addr, ETH_ADDR_BROADCAST,
                     targetsin->sin_addr);
  gettimeofday(&start, NULL);
  gettimeofday(&now, NULL);

  while (!foundit && num_sends < max_sends) {
    /* Send the sucker */
    rc = eth_send(ethsd, frame, sizeof(frame));
    if (rc != sizeof(frame)) {
     netutil_error("WARNING: %s: eth_send of ARP packet returned %u rather than expected %d bytes", __func__, rc, (int) sizeof(frame));
    }
    if(traceArp_callback!=NULL){
        /* TODO: First parameter "1" is a hardcoded value for Nmap's PacketTrace::SENT*/
        traceArp_callback(1, (u8 *) frame + ETH_HDR_LEN, ARP_HDR_LEN + ARP_ETHIP_LEN, &now);
    }
    num_sends++;

    listenrounds = 0;
    while (!foundit) {
      gettimeofday(&now, NULL);
      timeleft = timeouts[num_sends - 1] - TIMEVAL_SUBTRACT(now, start);
      if (timeleft < 0) {
        if (listenrounds > 0)
          break;
        else
          timeleft = 25000;
      }
      listenrounds++;
      /* Now listen until we reach our next timeout or get an answer */
      rc = read_arp_reply_pcap(pd, targetmac, &rcvdIP, timeleft,
                               &rcvdtime, traceArp_callback);
      if (rc == -1)
        netutil_fatal("%s: Received -1 response from readarp_reply_pcap", __func__);
      if (rc == 1) {
        /* Yay, I got one! But is it the right one? */
        if (rcvdIP.s_addr != targetsin->sin_addr.s_addr)
          continue; /* D'oh! */
        foundit = true; /* WOOHOO! */
      }
    }
  }

  /* OK - let's close up shop ... */
  pcap_close(pd);
  /* No need to close ethsd due to caching */
  return foundit;
}



static inline bool is_host_separator(int c) {
  return c == ' ' || c == '\r' || c == '\n' || c == '\t' || c == '\0';
}

/* Read a single host specification from a file, as for -iL and --excludefile.
   It returns the length of the string read; an overflow is indicated when the
   return value is >= n. Returns 0 if there was no specification to be read. The
   buffer is always null-terminated. */
size_t read_host_from_file(FILE *fp, char *buf, size_t n)
{
  int ch;
  size_t i;

  i = 0;
  ch = getc(fp);
  while (is_host_separator(ch) || ch == '#') {
    if (ch == '#') {
      /* Skip comments to the end of the line. */
      while ((ch = getc(fp)) != EOF && ch != '\n')
        ;
    } else {
      ch = getc(fp);
    }
  }
  while (ch != EOF && !(is_host_separator(ch) || ch == '#')) {
    if (i < n)
      buf[i] = ch;
    i++;
    ch = getc(fp);
  }
  if (ch != EOF)
    ungetc(ch, fp);
  if (i < n)
    buf[i] = '\0';
  else if (n > 0)
    /* Null-terminate even though it was too long. */
    buf[n - 1] = '\0';

  return i;
}


/* Return next target host specification from the supplied stream.
 * if parameter "random" is set to true, then the function will
 * return a random, non-reserved, IP address in decimal-dot notation */
char *grab_next_host_spec(FILE *inputfd, bool random, int argc, char **fakeargv) {
  static char host_spec[1024];
  struct in_addr ip;
  size_t n;

  if (random) {
    do {
      ip.s_addr = get_random_unique_u32();
    } while (ip_is_reserved(&ip));
    Strncpy(host_spec, inet_ntoa(ip), sizeof(host_spec));
  } else if (!inputfd) {
    return( (optind < argc)?  fakeargv[optind++] : NULL);
  } else { 
    n = read_host_from_file(inputfd, host_spec, sizeof(host_spec));
    if (n == 0)
      return NULL;
    else if (n >= sizeof(host_spec))
      netutil_fatal("One of the host specifications from your input file is too long (>= %u chars)", (unsigned int) sizeof(host_spec));
  }
  return host_spec;
}



/** Tries to increase the open file descriptor limit for this process.
  * @param "desired" is the number of desired max open descriptors. Pass a
  * negative value to set the maximum allowed.
  * @return the number of max open descriptors that could be set, or 0 in case
  * of failure.
  * @warning if "desired" is less than the current limit, no action is
  * performed. This function may only be used to increase the limit, not to
  * decrease it. */
int set_max_open_descriptors(int desired_max) {
 #ifndef WIN32
  struct rlimit r;
  int maxfds=-1;
  int flag=0;

  #if (defined(RLIMIT_OFILE) || defined(RLIMIT_NOFILE))
    
    #ifdef RLIMIT_NOFILE
        flag=RLIMIT_NOFILE; /* Linux  */
    #else
        flag=RLIMIT_OFILE;  /* BSD    */
    #endif

    if (!getrlimit(flag, &r)) {
        /* If current limit is less than the desired, try to increase it */
        if(r.rlim_cur < (rlim_t)desired_max){
            if(desired_max<0){
                r.rlim_cur=r.rlim_max; /* Set maximum */
            }else{
                r.rlim_cur = MIN( (int)r.rlim_max, desired_max );
            }
            if (setrlimit(flag, &r))
               ; // netutil_debug("setrlimit(%d, %p) failed", flag, r);
            if (!getrlimit(flag, &r)) {
                maxfds = r.rlim_cur;
                return maxfds;
            }else {
                return 0;
            }
        }
    }

  #endif /* (defined(RLIMIT_OFILE) || defined(RLIMIT_NOFILE)) */
 #endif /* !WIN32 */
 return 0;
}


/** Returns the open file descriptor limit for this process.
  * @return the number of max open descriptors or 0 in case of failure. */
int get_max_open_descriptors() {
 #ifndef WIN32
  struct rlimit r;
  int flag=0;

  #if (defined(RLIMIT_OFILE) || defined(RLIMIT_NOFILE))
    
    #ifdef RLIMIT_NOFILE
        flag=RLIMIT_NOFILE; /* Linux  */
    #else
        flag=RLIMIT_OFILE;  /* BSD    */
    #endif

    if (!getrlimit(flag, &r)) {
        return (int)r.rlim_cur;
    }

  #endif /* (defined(RLIMIT_OFILE) || defined(RLIMIT_NOFILE)) */
 #endif /* !WIN32 */
 return 0;
}


/* Maximize the open file descriptor limit for this process go up to the
   max allowed  */
int max_sd() {
  return set_max_open_descriptors(-1);
}
