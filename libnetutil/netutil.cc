/***************************************************************************
 * netutil.cc                                                              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2024 Nmap Software LLC ("The Nmap
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

/* Since OS X 10.7, we must declare whether we expect RFC 2292 or RFC 3542
   behavior from <netinet6/in6.h>. */
#define __APPLE_USE_RFC_3542

#if HAVE_CONFIG_H
#include "../nmap_config.h"
#endif

#include "nbase.h"

#ifndef WIN32
#include <sys/uio.h>
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

/* Define CMSG_* symbols for Solaris 9 and earlier. See
   http://wiki.opencsw.org/porting-faq#toc10. */
#if defined(__sun) || defined(__sun__)
# ifndef CMSG_ALIGN
#   ifdef __sun__
#     define CMSG_ALIGN(len) _CMSG_DATA_ALIGN (len)
#   else
      /* aligning to sizeof (long) is assumed to be portable (fd.o#40235) */
#     define CMSG_ALIGN(len) (((len) + sizeof (long) - 1) & ~(sizeof (long) - 1))
#   endif
# endif
# ifndef CMSG_SPACE
#   define CMSG_SPACE(len) (CMSG_ALIGN (sizeof (struct cmsghdr)) + CMSG_ALIGN (len))
# endif
# ifndef CMSG_LEN
#   define CMSG_LEN(len) (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len))
# endif
#endif /* Solaris */

#ifdef WIN32
typedef unsigned __int32 u_int32_t;
typedef unsigned __int16 u_int16_t;
typedef unsigned __int8 u_int8_t;
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_LINUX_RTNETLINK_H
#include <linux/rtnetlink.h>
#endif

#ifndef NETINET_IN_SYSTM_H  /* This guarding is needed for at least some versions of OpenBSD */
#include <netinet/in_systm.h>
#define NETINET_IN_SYSTM_H
#endif

#include "netutil.h"

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
#include <net/if_arp.h>

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#define NBASE_MAX_ERR_STR_LEN 1024  /* Max length of an error message */

#ifndef PCAP_NETMASK_UNKNOWN
/* libpcap before 1.1.1 (e.g. WinPcap) doesn't handle this specially, so just use 0 netmask */
#define PCAP_NETMASK_UNKNOWN 0
#endif

/** Print fatal error messages to stderr and then exits. A newline
    character is printed automatically after the supplied text.
 * @warning This function does not return because it calls exit() */
void netutil_fatal(const char *str, ...){
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
  long strtolbyte = 0; // used to check strtol() return boundaries

  for(;*c;c++){
    switch(s){
    case SLASH:
      // parse \x00 string
      if(*c == 'x'){// just ignore this char
      	base = 16;
        break;
      }
      if(isxdigit(*c)){
        strtolbyte = strtol(c, &n, base);
        if((strtolbyte < 0) || (strtolbyte > 255)){
          if(errstr) Snprintf(errstr, errstrlen, "invalid ipv4 address format");
          return OP_FAILURE;
        }
        *d++ = (u8) strtolbyte;
        c = n-1;
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

/* Internal helper for resolve and resolve_numeric. addl_flags is ored into
   hints.ai_flags, so you can add AI_NUMERICHOST. */
static int resolve_internal(const char *hostname, unsigned short port,
  struct sockaddr_storage *ss, size_t *sslen, int af, int addl_flags) {
  struct addrinfo hints;
  struct addrinfo *result;
  char portbuf[16];
  char *servname = NULL;
  int rc;

  assert(hostname);
  assert(ss);
  assert(sslen);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = af;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags |= addl_flags;

  /* Make the port number a string to give to getaddrinfo. */
  if (port != 0) {
    rc = Snprintf(portbuf, sizeof(portbuf), "%hu", port);
    assert(rc >= 0 && (size_t) rc < sizeof(portbuf));
    servname = portbuf;
  }

  rc = getaddrinfo(hostname, servname, &hints, &result);
  if (rc != 0)
    return rc;
  if (result == NULL)
    return EAI_NONAME;
  assert(result->ai_addrlen > 0 && result->ai_addrlen <= (int) sizeof(struct sockaddr_storage));
  *sslen = result->ai_addrlen;
  memcpy(ss, result->ai_addr, *sslen);
  freeaddrinfo(result);

  return 0;
}

/* Resolves the given hostname or IP address with getaddrinfo, and stores the
   first result (if any) in *ss and *sslen. The value of port will be set in the
   appropriate place in *ss; set to 0 if you don't care. af may be AF_UNSPEC, in
   which case getaddrinfo may return e.g. both IPv4 and IPv6 results; which one
   is first depends on the system configuration. Returns 0 on success, or a
   getaddrinfo return code (suitable for passing to gai_strerror) on failure.
   *ss and *sslen are always defined when this function returns 0. */
int resolve(const char *hostname, unsigned short port,
  struct sockaddr_storage *ss, size_t *sslen, int af) {
  return resolve_internal(hostname, port, ss, sslen, af, 0);
}

/* As resolve, but do not do DNS resolution of hostnames; the first argument
   must be the string representation of a numeric IP address. */
int resolve_numeric(const char *ip, unsigned short port,
  struct sockaddr_storage *ss, size_t *sslen, int af) {
  return resolve_internal(ip, port, ss, sslen, af, AI_NUMERICHOST);
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
int ip_is_reserved(const struct sockaddr_storage *addr)
{
  static struct addrset *reserved = NULL;
  assert(addr);

  if (reserved == NULL) {
    reserved = addrset_new();

    // https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
    addrset_add_spec(reserved, "0.0.0.0/8", AF_INET, 0);
    addrset_add_spec(reserved, "10.0.0.0/8", AF_INET, 0);
    addrset_add_spec(reserved, "100.64.0.0/10", AF_INET, 0);
    addrset_add_spec(reserved, "127.0.0.0/8", AF_INET, 0);
    addrset_add_spec(reserved, "169.254.0.0/16", AF_INET, 0);
    addrset_add_spec(reserved, "172.16.0.0/12", AF_INET, 0);
    addrset_add_spec(reserved, "192.0.0.0/24", AF_INET, 0);
    //addrset_add_spec(exceptions, "192.0.0.9", AF_INET, 0);
    //addrset_add_spec(exceptions, "192.0.0.10", AF_INET, 0);
    addrset_add_spec(reserved, "192.0.2.0/24", AF_INET, 0);
    addrset_add_spec(reserved, "192.168.0.0/16", AF_INET, 0);
    addrset_add_spec(reserved, "198.18.0.0/15", AF_INET, 0);
    addrset_add_spec(reserved, "198.51.100.0/24", AF_INET, 0);
    addrset_add_spec(reserved, "203.0.113.0/24", AF_INET, 0);
    addrset_add_spec(reserved, "240.0.0.0/4", AF_INET, 0);
    addrset_add_spec(reserved, "255.255.255.255", AF_INET, 0);

    // https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
    addrset_add_spec(reserved, "::1", AF_INET6, 0);
    addrset_add_spec(reserved, "::", AF_INET6, 0);
    addrset_add_spec(reserved, "::ffff:0:0/96", AF_INET6, 0);
    addrset_add_spec(reserved, "64:ff9b:1::/48", AF_INET6, 0);
    addrset_add_spec(reserved, "100::/64", AF_INET6, 0);
    addrset_add_spec(reserved, "100::/64", AF_INET6, 0);
    addrset_add_spec(reserved, "2001::/23", AF_INET6, 0);
    //addrset_add_spec(exceptions, "2001:1::1", AF_INET6, 0);
    //addrset_add_spec(exceptions, "2001:1::2", AF_INET6, 0);
    //addrset_add_spec(exceptions, "2001:1::3", AF_INET6, 0);
    //addrset_add_spec(exceptions, "2001:3::/32", AF_INET6, 0);
    //addrset_add_spec(exceptions, "2001:4:112::/48", AF_INET6, 0);
    //addrset_add_spec(exceptions, "2001:20::/28", AF_INET6, 0);
    //addrset_add_spec(exceptions, "2001:30::/28", AF_INET6, 0);
    addrset_add_spec(reserved, "2001:db8::/32", AF_INET6, 0);
    addrset_add_spec(reserved, "2002::/16", AF_INET6, 0);
    addrset_add_spec(reserved, "3fff::/20", AF_INET6, 0);
    addrset_add_spec(reserved, "5f00::/16", AF_INET6, 0);
    addrset_add_spec(reserved, "fc00::/7", AF_INET6, 0);
    addrset_add_spec(reserved, "fe80::/10", AF_INET6, 0);
  }

  return addrset_contains(reserved, (struct sockaddr *)addr);
}

/* A trivial functon that maintains a cache of IP to MAC Address
   entries.  If the command is MACCACHE_GET, this func looks for the
   IPv4 address in ss and fills in the 'mac' parameter and returns
   true if it is found.  Otherwise (not found), the function returns
   false.  If the command is MACCACHE_SET, the function adds an entry
   with the given ip (ss) and mac address.  An existing entry for the
   IP ss will be overwritten with the new MAC address.  true is always
   returned for the set command. */
#define MACCACHE_GET 1
#define MACCACHE_SET 2
static int do_mac_cache(int command, const struct sockaddr_storage *ss, u8 *mac) {
  struct MacCache {
    struct sockaddr_storage ip;
    u8 mac[6];
  };
  static struct MacCache *Cache = NULL;
  static int MacCapacity = 0;
  static int MacCacheSz = 0;
  int i;

  if (command == MACCACHE_GET) {
    for (i = 0; i < MacCacheSz; i++) {
      if (sockaddr_storage_cmp(&Cache[i].ip, ss) == 0) {
        memcpy(mac, Cache[i].mac, 6);
        return 1;
      }
    }
    return 0;
  }
  assert(command == MACCACHE_SET);
  if (MacCacheSz == MacCapacity) {
    if (MacCapacity == 0)
      MacCapacity = 32;
    else
      MacCapacity <<= 2;
    Cache = (struct MacCache *) safe_realloc(Cache, MacCapacity * sizeof(struct MacCache));
  }

  /* Ensure that it isn't already there ... */
  for (i = 0; i < MacCacheSz; i++) {
    if (sockaddr_storage_cmp(&Cache[i].ip, ss) == 0) {
      memcpy(Cache[i].mac, mac, 6);
      return 1;
    }
  }

  /* Add it to the end of the list */
  memcpy(&Cache[i].ip, ss, sizeof(struct sockaddr_storage));
  memcpy(Cache[i].mac, mac, 6);
  MacCacheSz++;
  return 1;
}

/* A couple of trivial functions that maintain a cache of IP to MAC
 * Address entries. Function mac_cache_get() looks for the IPv4 address
 * in ss and fills in the 'mac' parameter and returns true if it is
 * found.  Otherwise (not found), the function returns false.
 * Function mac_cache_set() adds an entry with the given ip (ss) and
 * mac address.  An existing entry for the IP ss will be overwritten
 * with the new MAC address.  mac_cache_set() always returns true.
 * WARNING: The caller must ensure that the supplied "ss" is of family
 * AF_INET. Otherwise the function will return 0 and there would be
 * no way for the caller to tell tell the difference between an error
 * or a cache miss.*/
int mac_cache_get(const struct sockaddr_storage *ss, u8 *mac){
    return do_mac_cache(MACCACHE_GET, ss, mac);
}
int mac_cache_set(const struct sockaddr_storage *ss, u8 *mac){
    return do_mac_cache(MACCACHE_SET, ss, mac);
}

/* Standard BSD internet checksum routine. Uses libdnet helper functions. */
unsigned short in_cksum(u16 *ptr,int nbytes) {
  int sum;

   sum = ip_cksum_add(ptr, nbytes, 0);

  return ip_cksum_carry(sum);

  return 0;
}


/* Return true iff this Next Header type is an extension header we must skip to
   get to the upper-layer header. Types for which neither this function nor
   ipv6_is_upperlayer return true are unknown and could be either. */
static int ipv6_is_extension_header(u8 type)
{
  switch (type) {
  case IP_PROTO_HOPOPTS:
  case IP_PROTO_DSTOPTS:
  case IP_PROTO_ROUTING:
  case IP_PROTO_FRAGMENT:
  /*
  case IP_PROTO_ESP:
  case IP_PROTO_AH:
  */
    return 1;
  default:
    return 0;
  }
}

/* Return true iff this Next Header type is a known upper-layer protocol, one
   that isn't followed by any more headers. Types for which neither this
   function nor ipv6_is_upperlayer return true are unknown and could be
   either. */
static int ipv6_is_upperlayer(u8 type)
{
  switch (type) {
  case IP_PROTO_NONE:
  case IP_PROTO_TCP:
  case IP_PROTO_UDP:
  case IP_PROTO_ICMP:
  case IP_PROTO_ICMPV6:
  case IP_PROTO_SCTP:
    return 1;
  default:
    return 0;
  }
}

/* upperlayer_only controls whether we require a known upper-layer protocol at
   the end of the chain, or return the last readable header even if it is not an
   upper-layer protocol (may even be another extension header). */
static const void *ipv6_get_data_primitive(const struct ip6_hdr *ip6,
  unsigned int *len, u8 *nxt, bool upperlayer_only)
{
  const unsigned char *p, *end;

  if (*len < sizeof(*ip6))
    return NULL;

  p = (unsigned char *) ip6;
  end = p + *len;

  *nxt = ip6->ip6_nxt;
  p += sizeof(*ip6);
  while (p < end && ipv6_is_extension_header(*nxt)) {
    if (p + 2 > end)
      return NULL;
    *nxt = *p;
    p += (*(p + 1) + 1) * 8;
  }

  *len = end - p;
  if (upperlayer_only && !ipv6_is_upperlayer(*nxt))
    return NULL;

  return (char *) p;
}

static const void *ip_get_data_primitive(const void *packet, unsigned int *len,
  struct abstract_ip_hdr *hdr, bool upperlayer_only) {
  const struct ip *ip;

  ip = (struct ip *) packet;
  if (*len >= 20 && ip->ip_v == 4) {
    struct sockaddr_in *sin;

    hdr->version = 4;

    sin = (struct sockaddr_in *) &hdr->src;
    memset(&hdr->src, 0, sizeof(hdr->src));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip->ip_src.s_addr;

    sin = (struct sockaddr_in *) &hdr->dst;
    memset(&hdr->dst, 0, sizeof(hdr->dst));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip->ip_dst.s_addr;

    hdr->proto = ip->ip_p;
    hdr->ttl = ip->ip_ttl;
    hdr->ipid = ntohs(ip->ip_id);
    return ipv4_get_data(ip, len);
  } else if (*len >= 40 && ip->ip_v == 6) {
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) ip;
    struct sockaddr_in6 *sin6;

    hdr->version = 6;

    sin6 = (struct sockaddr_in6 *) &hdr->src;
    memset(&hdr->src, 0, sizeof(hdr->src));
    sin6->sin6_family = AF_INET6;
    memcpy(&sin6->sin6_addr, &ip6->ip6_src, IP6_ADDR_LEN);

    sin6 = (struct sockaddr_in6 *) &hdr->dst;
    memset(&hdr->dst, 0, sizeof(hdr->dst));
    sin6->sin6_family = AF_INET6;
    memcpy(&sin6->sin6_addr, &ip6->ip6_dst, IP6_ADDR_LEN);

    hdr->ttl = ip6->ip6_hlim;
    hdr->ipid = ntohl(ip6->ip6_flow & IP6_FLOWLABEL_MASK);
    return ipv6_get_data_primitive(ip6, len, &hdr->proto, upperlayer_only);
  }

  return NULL;
}

/* Find the beginning of the data payload in the IP packet beginning at packet.
   Returns the beginning of the payload, updates *len to be the length of the
   payload, and fills in hdr if successful. Otherwise returns NULL and *hdr is
   undefined. */
const void *ip_get_data(const void *packet, unsigned int *len,
  struct abstract_ip_hdr *hdr) {
  return ip_get_data_primitive(packet, len, hdr, true);
}

/* As ip_get_data, except that it doesn't insist that the payload be a known
   upper-layer protocol. This can matter in IPv6 where the last element of a nh
   chain may be a protocol we don't know about. */
const void *ip_get_data_any(const void *packet, unsigned int *len,
  struct abstract_ip_hdr *hdr) {
  return ip_get_data_primitive(packet, len, hdr, false);
}

/* Get the upper-layer protocol from an IPv4 packet. */
const void *ipv4_get_data(const struct ip *ip, unsigned int *len)
{
  unsigned int header_len;

  if (*len < 20)
    return NULL;
  header_len = ip->ip_hl * 4;
  if (header_len < sizeof(*ip))
    return NULL;
  if (header_len > *len)
    return NULL;
  *len -= header_len;

  return (char *) ip + header_len;
}

/* Get the upper-layer protocol from an IPv6 packet. This skips over known
   extension headers. The length of the upper-layer payload is stored in *len.
   The protocol is stored in *nxt. Returns NULL in case of error. */
const void *ipv6_get_data(const struct ip6_hdr *ip6, unsigned int *len, u8 *nxt)
{
  return ipv6_get_data_primitive(ip6, len, nxt, true);
}

/* Get the protocol payload from an IPv6 packet. This skips over known extension
   headers. It differs from ipv6_get_data in that it will return a result even
   if the final header is not a known upper-layer protocol. */
const void *ipv6_get_data_any(const struct ip6_hdr *ip6, unsigned int *len, u8 *nxt)
{
  return ipv6_get_data_primitive(ip6, len, nxt, false);
}

const void *icmp_get_data(const struct icmp_hdr *icmp, unsigned int *len)
{
  unsigned int header_len;

  if (icmp->icmp_type == ICMP_TIMEXCEED || icmp->icmp_type == ICMP_UNREACH)
    header_len = 8;
  else
    netutil_fatal("%s passed ICMP packet with unhandled type %d", __func__, icmp->icmp_type);
  if (header_len > *len)
    return NULL;
  *len -= header_len;

  return (char *) icmp + header_len;
}

const void *icmpv6_get_data(const struct icmpv6_hdr *icmpv6, unsigned int *len)
{
  unsigned int header_len;

  if (icmpv6->icmpv6_type == ICMPV6_TIMEXCEED || icmpv6->icmpv6_type == ICMPV6_UNREACH)
    header_len = 8;
  else
    netutil_fatal("%s passed ICMPv6 packet with unhandled type %d", __func__, icmpv6->icmpv6_type);
  if (header_len > *len)
    return NULL;
  *len -= header_len;

  return (char *) icmpv6 + header_len;
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
  sum = ip_cksum_carry(sum);
  /* RFC 768: "If the computed  checksum  is zero,  it is transmitted  as all
   * ones (the equivalent  in one's complement  arithmetic).   An all zero
   * transmitted checksum  value means that the transmitter  generated  no
   * checksum" */
  if (proto == IP_PROTO_UDP && sum == 0)
    sum = 0xFFFF;

  return sum;
}

/* Calculate the Internet checksum of some given data concatenated with the
   IPv6 pseudo-header. See RFC 2460 section 8.1. */
u16 ipv6_pseudoheader_cksum(const struct in6_addr *src,
  const struct in6_addr *dst, u8 nxt, u32 len, const void *hstart) {
  struct {
    struct in6_addr src;
    struct in6_addr dst;
    u32 length;
    u8 z0, z1, z2;
    u8 nxt;
  } hdr;
  int sum;

  hdr.src = *src;
  hdr.dst = *dst;
  hdr.z0 = hdr.z1 = hdr.z2 = 0;
  hdr.length = htonl(len);
  hdr.nxt = nxt;

  sum = ip_cksum_add(&hdr, sizeof(hdr), 0);
  sum = ip_cksum_add(hstart, len, sum);
  sum = ip_cksum_carry(sum);
  /* RFC 2460: "Unlike IPv4, when UDP packets are originated by an IPv6 node,
     the UDP checksum is not optional.  That is, whenever originating a UDP
     packet, an IPv6 node must compute a UDP checksum over the packet and the
     pseudo-header, and, if that computation yields a result of zero, it must be
     changed to hex FFFF for placement in the UDP header." */
  if (nxt == IP_PROTO_UDP && sum == 0)
    sum = 0xFFFF;

  return sum;
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

/* Other than WIN32, what these systems have in common is that they use BPF for
   packet capture. (Solaris 10 and earlier used DLPI and had valid selectable
   fds.) */
#if defined(WIN32) || defined(MACOSX) || (defined(FREEBSD) && (__FreeBSD_version < 500000)) || defined(SOLARIS_BPF_PCAP_CAPTURE) || defined(OPENBSD)
/* Returns whether the system supports pcap_get_selectable_fd() properly */
int pcap_selectable_fd_valid() {
  return 0;
}

/* Call this instead of pcap_get_selectable_fd directly (or your code
   won't compile on Windows).  On systems which don't seem to support
   the pcap_get_selectable_fd() function properly, returns -1,
   otherwise simply calls pcap_selectable_fd and returns the
   results.  If you just want to test whether the function is supported,
   use pcap_selectable_fd_valid() instead. */
int my_pcap_get_selectable_fd(pcap_t *p) {
  return -1;
}
#else
int pcap_selectable_fd_valid() {
  return 1;
}
int my_pcap_get_selectable_fd(pcap_t *p) {
  return pcap_get_selectable_fd(p);
}
#endif

/* Are we guaranteed to be able to read exactly one frame for each time the pcap
   fd is selectable? If not, it's possible for the fd to become selectable, then
   for pcap_dispatch to buffer two or more frames, and return only the first one
   Because select doesn't know about pcap's buffer, the fd does not become
   selectable again, even though another pcap_next_ex would succeed. On these
   platforms, we must do a non-blocking read from the fd before doing a select
   on the fd.

   It is guaranteed that if pcap_selectable_fd_valid() is false, then so is the
   return value of this function. */
int pcap_selectable_fd_one_to_one() {
#ifdef SOLARIS
  return 0;
#endif
  return pcap_selectable_fd_valid();
}


/* returns -1 if we can't use select() on the pcap device, 0 for timeout, and
 * >0 for success. If select() fails we bail out because it couldn't work with
 * the file descriptor we got from my_pcap_get_selectable_fd()
 */
int pcap_select(pcap_t *p, long usecs) {
  int ret;
#ifdef WIN32
  DWORD msec_timeout = usecs / 1000;
  HANDLE event = pcap_getevent(p);
  DWORD result = WaitForSingleObject(event, msec_timeout);

  switch(result) {
    case WAIT_OBJECT_0:
      ret = 1;
      break;
    case WAIT_TIMEOUT:
      ret = 0;
      break;
    case WAIT_FAILED:
      ret = -1;
      netutil_error("%s: WaitForSingleObject failed: %d", __func__, GetLastError());
      break;
    default:
      ret = -1;
      netutil_fatal("%s: WaitForSingleObject returned unknown result: %x", __func__, result);
      break;
  }

#else
  long elapsed = 0;
  struct timeval tv, start, now;
  int fd;
  fd_set rfds;

  if ((fd = my_pcap_get_selectable_fd(p)) == -1)
    return -1;

  FD_ZERO(&rfds);
  checked_fd_set(fd, &rfds);

  gettimeofday(&start, NULL);
  do {
    errno = 0;
    tv.tv_sec = (usecs - elapsed) / 1000000;
    tv.tv_usec = (usecs - elapsed) % 1000000;

    ret = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (ret == -1) {
      if (errno == EINTR) {
        gettimeofday(&now, NULL);
        elapsed = TIMEVAL_SUBTRACT(now, start);
        netutil_error("%s: %s", __func__, strerror(errno));
      }
      else
        netutil_fatal("Your system does not support select()ing on pcap devices (%s). PLEASE REPORT THIS ALONG WITH DETAILED SYSTEM INFORMATION TO THE nmap-dev MAILING LIST!", strerror(errno));
    }
  } while (ret == -1 && elapsed < usecs);
#endif

  return ret;
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

      Snprintf(p, bufsize, "mss %hu", (unsigned short) ntohs(tmpshort));
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

      Snprintf(p, bufsize, "timestamp %lu %lu", (unsigned long) ntohl(tmpword1),
               (unsigned long) ntohl(tmpword2));
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



/* A trivial function used with qsort to sort the routes by netmask and metric */
static int routecmp(const void *a, const void *b) {
  struct sys_route *r1 = (struct sys_route *) a;
  struct sys_route *r2 = (struct sys_route *) b;
  if (r1->dest.ss_family < r2->dest.ss_family)
    return -1;
  else if (r1->dest.ss_family > r2->dest.ss_family)
    return 1;

  if (r1->netmask_bits < r2->netmask_bits)
    return 1;
  else if (r1->netmask_bits > r2->netmask_bits)
    return -1;

  if (r1->metric < r2->metric)
    return -1;
  else if (r1->metric > r2->metric)
    return 1;

  /* Compare addresses of equal elements to make the sort stable, as suggested
     by the Glibc manual. */
  if (a < b)
    return -1;
  else if (a > b)
    return 1;
  else
    return 0;
}



/* Convert an address to a string and back again. The first parsing step
   eliminates magical OS-specific syntax, for example on OS X, fe80:4::X:X:X:X
   becomes "fe80::X:X:X:X" (the "4" in this case is another way of writing the
   zone ID, like "%en0"; i.e., in this case en0 is interface number 4). This
   must be done before e.g. comparing addresses by netmask. */
static int canonicalize_address(const struct sockaddr_storage *ss,
  struct sockaddr_storage *output) {
  char canonical_ip_string[NI_MAXHOST];
  struct addrinfo hints;
  struct addrinfo *ai;
  int rc;

  /* Convert address to string. */
  rc = getnameinfo((struct sockaddr *) ss, sizeof(*ss),
    canonical_ip_string, sizeof(canonical_ip_string), NULL, 0, NI_NUMERICHOST);
  if (rc != 0) {
    /* Don't care. */
    *output = *ss;
    return 0;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = ss->ss_family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags |= AI_NUMERICHOST;

  rc = getaddrinfo(canonical_ip_string, NULL, &hints, &ai);
  if (rc != 0 || ai == NULL)
    return -1;
  assert(ai->ai_addrlen > 0 && ai->ai_addrlen <= (int) sizeof(*output));
  memcpy(output, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(ai);

  return 0;
}

static int collect_dnet_interfaces(const struct intf_entry *entry, void *arg) {
  struct dnet_collector_route_nfo *dcrn = (struct dnet_collector_route_nfo *) arg;
  bool primary_done;
  unsigned int num_aliases_done;
  struct sockaddr_storage tmpss;
  int rc;

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
      if ( (addr_ntos(&entry->intf_addr, (struct sockaddr *) &tmpss) == -1)
#ifdef AF_LINK
              || (tmpss.ss_family == AF_LINK)
#endif
         ) {
        dcrn->ifaces[dcrn->numifaces].addr.ss_family = 0;
      } else {
        rc = canonicalize_address(&tmpss, &dcrn->ifaces[dcrn->numifaces].addr);
        assert(rc == 0);
      }
      dcrn->ifaces[dcrn->numifaces].netmask_bits = entry->intf_addr.addr_bits;
      primary_done = true;
    } else if (num_aliases_done < entry->intf_alias_num) {
      if ( (addr_ntos(&entry->intf_alias_addrs[num_aliases_done], (struct sockaddr *) &tmpss) == -1)
#ifdef AF_LINK
              || (tmpss.ss_family == AF_LINK)
#endif
         ) {
        dcrn->ifaces[dcrn->numifaces].addr.ss_family = 0;
      } else {
        rc = canonicalize_address(&tmpss, &dcrn->ifaces[dcrn->numifaces].addr);
        assert(rc == 0);
      }
      dcrn->ifaces[dcrn->numifaces].netmask_bits = entry->intf_alias_addrs[num_aliases_done].addr_bits;
      num_aliases_done++;
    }

    /* OK, address/netmask found.  Let's get the name */
    Strncpy(dcrn->ifaces[dcrn->numifaces].devname, entry->intf_name,
      sizeof(dcrn->ifaces[dcrn->numifaces].devname));
    Strncpy(dcrn->ifaces[dcrn->numifaces].devfullname, entry->intf_name,
      sizeof(dcrn->ifaces[dcrn->numifaces].devfullname));

    /* Interface type */
    if (entry->intf_type == INTF_TYPE_ETH && (entry->intf_flags & INTF_FLAG_NOARP) == 0) {
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

    dcrn->ifaces[dcrn->numifaces].ifindex = entry->intf_index;

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

static struct interface_info *mydevs = NULL;
/* Returns an allocated array of struct interface_info representing the
   available interfaces. The number of interfaces is returned in *howmany. This
   function just does caching of results; the real work is done in
   getinterfaces_dnet().
   On error, NULL is returned, howmany is set to -1 and the supplied
   error buffer "errstr", if not NULL, will contain an error message. */
struct interface_info *getinterfaces(int *howmany, char *errstr, size_t errstrlen) {
  static int numifaces = 0;

  if (mydevs == NULL) {
    mydevs = getinterfaces_dnet(&numifaces, errstr, errstrlen);
  }

  /* These will propagate any error produced in getinterfaces_xxxx() to
   * the caller. */
  if (howmany)
    *howmany = numifaces;
  return mydevs;
}

void freeinterfaces(void) {
  free(mydevs);
  mydevs = NULL;
}

/* The 'dev' passed in must be at least 32 bytes long. Returns 0 on success. */
int ipaddr2devname(char *dev, const struct sockaddr_storage *addr) {
  struct interface_info *ifaces;
  int numifaces;
  int i;

  ifaces = getinterfaces(&numifaces, NULL, 0);

  if (ifaces == NULL)
    return -1;

  for (i = 0; i < numifaces; i++) {
    if (sockaddr_storage_cmp(&ifaces[i].addr, addr) == 0) {
      Strncpy(dev, ifaces[i].devname, 32);
      return 0;
    }
  }

  return -1;
}

int devname2ipaddr(char *dev, int af, struct sockaddr_storage *addr) {
  struct interface_info *ifaces;
  int numifaces;
  int i;
  ifaces = getinterfaces(&numifaces, NULL, 0);

  if (ifaces == NULL)
    return -1;

  for (i = 0; i < numifaces; i++) {
    if (af == ifaces[i].addr.ss_family && !strcmp(dev, ifaces[i].devfullname)) {
      *addr = ifaces[i].addr;
      return 0;
    }
  }
  return -1;
}

/* Looks for an interface with the given name (iname) and address
   family type, and returns the corresponding interface_info if found.
   Will accept a match of devname or devfullname. Returns NULL if
   none found */
struct interface_info *getInterfaceByName(const char *iname, int af) {
  struct interface_info *ifaces;
  int numifaces = 0;
  int ifnum;

  ifaces = getinterfaces(&numifaces, NULL, 0);

  for (ifnum = 0; ifnum < numifaces; ifnum++) {
    if ((strcmp(ifaces[ifnum].devfullname, iname) == 0 ||
        strcmp(ifaces[ifnum].devname, iname) == 0) &&
        ifaces[ifnum].addr.ss_family == af)
      return &ifaces[ifnum];
  }

  return NULL;
}


int sockaddr_equal(const struct sockaddr_storage *a,
  const struct sockaddr_storage *b) {

  if (a->ss_family == AF_INET && b->ss_family == AF_INET) {
    struct sockaddr_in *sa, *sb;

    sa = (struct sockaddr_in *) a;
    sb = (struct sockaddr_in *) b;

    return sa->sin_addr.s_addr == sb->sin_addr.s_addr;
  } if (a->ss_family == AF_INET6 && b->ss_family == AF_INET6) {
    struct sockaddr_in6 *sa, *sb;

    sa = (struct sockaddr_in6 *) a;
    sb = (struct sockaddr_in6 *) b;

    return memcmp(sa->sin6_addr.s6_addr, sb->sin6_addr.s6_addr, sizeof(sa->sin6_addr.s6_addr)) == 0;
  }

  return 0;
}

int sockaddr_equal_netmask(const struct sockaddr_storage *a,
  const struct sockaddr_storage *b, u16 nbits) {
  unsigned char netmask[IP6_ADDR_LEN];

  addr_btom(nbits, netmask, sizeof(netmask));

  if (a->ss_family == AF_INET && b->ss_family == AF_INET) {
    struct in_addr *sa, *sb, *sn;

    sa = &((struct sockaddr_in *) a)->sin_addr;
    sb = &((struct sockaddr_in *) b)->sin_addr;
    sn = (struct in_addr *) netmask;

    return (sa->s_addr & sn->s_addr) == (sb->s_addr & sn->s_addr);
  } else if (a->ss_family == AF_INET6 && b->ss_family == AF_INET6) {
    struct in6_addr *sa, *sb, *sn;
    unsigned int i;

    sa = &((struct sockaddr_in6 *) a)->sin6_addr;
    sb = &((struct sockaddr_in6 *) b)->sin6_addr;
    sn = (struct in6_addr *) netmask;

    for (i = 0; i < sizeof(sa->s6_addr); i++) {
      if ((sa->s6_addr[i] & sn->s6_addr[i]) != (sb->s6_addr[i] & sn->s6_addr[i])) {
        return 0;
      }
    }

    return 1;
  }

  return 0;
}

int sockaddr_equal_zero(const struct sockaddr_storage *s) {
  if (s->ss_family == AF_INET) {
    const struct sockaddr_in *sin;

    sin = (struct sockaddr_in *) s;
    return sin->sin_addr.s_addr == 0;
  } if (s->ss_family == AF_INET6) {
    const struct sockaddr_in6 *sin6;

    sin6 = (struct sockaddr_in6 *) s;
    return memcmp(sin6->sin6_addr.s6_addr, IP6_ADDR_UNSPEC, IP6_ADDR_LEN) == 0;
  }

  return 0;
}

/* This is a helper for getsysroutes_dnet. Once the table of routes is in
   place, this function assigns each to an interface and removes any routes
   that can't be assigned. */
static struct dnet_collector_route_nfo *sysroutes_dnet_find_interfaces(struct dnet_collector_route_nfo *dcrn)
{
  struct interface_info *ifaces;
  int numifaces = 0;
  int i, j;
  int changed=0;

  if( (ifaces=getinterfaces(&numifaces, NULL, 0))==NULL )
    return NULL;
  for (i = 0; i < dcrn->numroutes; i++) {
    if (dcrn->routes[i].device != NULL)
      continue;

    /* First we match up routes whose gateway or destination address
       directly matches the address of an interface. */
    struct sys_route *route = &dcrn->routes[i];
    struct sockaddr_storage *routeaddr;

    /* First see if the gateway was set */
    if (sockaddr_equal_zero(&route->gw))
      routeaddr = &dcrn->routes[i].dest;
    else
      routeaddr = &dcrn->routes[i].gw;

    for (j = 0; j < numifaces; j++) {
      if (sockaddr_equal_netmask(&ifaces[j].addr, routeaddr, ifaces[j].netmask_bits)) {
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
        if (sockaddr_equal(&dcrn->routes[i].gw, &dcrn->routes[j].dest)
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

      Strncpy(destbuf, inet_ntop_ez(&dcrn->routes[i].dest, sizeof(dcrn->routes[i].dest)), sizeof(destbuf));
      Strncpy(gwbuf, inet_ntop_ez(&dcrn->routes[i].gw, sizeof(dcrn->routes[i].gw)), sizeof(gwbuf));
      /*
      netutil_error("WARNING: Unable to find appropriate interface for system route to %s/%u gw %s",
        destbuf, dcrn->routes[i].netmask_bits, gwbuf);
      */
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

  /* Make sure we have room for the new route */
  if (dcrn->numroutes >= dcrn->capacity) {
    dcrn->capacity <<= 2;
    dcrn->routes = (struct sys_route *) safe_realloc(dcrn->routes, dcrn->capacity * sizeof(struct sys_route));
  }

  /* Now for the important business */
  addr_ntos(&entry->route_dst, (struct sockaddr *) &dcrn->routes[dcrn->numroutes].dest);
  dcrn->routes[dcrn->numroutes].netmask_bits = entry->route_dst.addr_bits;
  addr_ntos(&entry->route_gw, (struct sockaddr *) &dcrn->routes[dcrn->numroutes].gw);
  dcrn->routes[dcrn->numroutes].metric = entry->metric;
  dcrn->routes[dcrn->numroutes].device = getInterfaceByName(entry->intf_name, dcrn->routes[dcrn->numroutes].dest.ss_family);
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
  assert(howmany);

  if (routes != NULL) {
    /* We have it cached. */
    *howmany = numroutes;
    return routes;
  }

  routes = getsysroutes_dnet(howmany, errstr, errstrlen);

  /* Check if we managed to get the routes and sort them if we did */
  if(routes==NULL){
    *howmany=-1;
    return NULL;
  }else{
    numroutes = *howmany;
    /* Ensure that the route array is sorted by netmask and metric */
    qsort(routes, numroutes, sizeof(routes[0]), routecmp);
  }
  return routes;
}


/* Tries to determine whether the supplied address corresponds to
 * localhost. (eg: the address is something like 127.x.x.x, the address
 * matches one of the local network interfaces' address, etc).
 * Returns 1 if the address is thought to be localhost and 0 otherwise */
int islocalhost(const struct sockaddr_storage *ss) {
  char dev[128];
  struct sockaddr_in *sin = NULL;
  struct sockaddr_in6 *sin6 = NULL;

  if (ss->ss_family == AF_INET){
    sin = (struct sockaddr_in *) ss;
    /* If it is 0.0.0.0 or starts with 127 then it is probably localhost. */
    if ((sin->sin_addr.s_addr & htonl(0xFF000000)) == htonl(0x7F000000))
      return 1;

    if (!(sin->sin_addr.s_addr))
      return 1;
  } else {
    sin6 = (struct sockaddr_in6 *) ss;
    /* If it is ::0 or ::1 then it is probably localhost. */
    if (memcmp(&(sin6->sin6_addr), IP6_ADDR_UNSPEC, IP6_ADDR_LEN) == 0)
      return 1;
    if (memcmp(&(sin6->sin6_addr), IP6_ADDR_LOOPBACK, IP6_ADDR_LEN) == 0)
      return 1;
  }

  /* If it is the same addy as a local interface, then it is
     probably localhost */
  if (ipaddr2devname(dev, ss) != -1)
    return 1;

  /* OK, so to a first approximation, this addy is probably not
     localhost */
  return 0;
}


char *nexthdrtoa(u8 nextheader, int acronym){

static char buffer[129];
memset(buffer, 0, 129);

#define HDRTOA(num, short_name, long_name) \
  case num: \
    strncpy(buffer, acronym ? short_name : long_name, 128);\
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
    strncpy(buffer, acronym ? "unknown" : "Unknown protocol", 128);\
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

  struct tcp_hdr *tcp = NULL;           /* TCP header structure.             */
  struct udp_hdr *udp = NULL;           /* UDP header structure.             */
  struct sctp_hdr *sctp = NULL;         /* SCTP header structure.            */
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
    const struct ip *ip;
    const struct sockaddr_in *sin;

    ip = (struct ip *) packet;

    /* Obtain IP source and destination info */
    sin = (struct sockaddr_in *) &hdr.src;
    inet_ntop(AF_INET, (void *)&sin->sin_addr.s_addr, srchost, sizeof(srchost));
    sin = (struct sockaddr_in *) &hdr.dst;
	inet_ntop(AF_INET, (void *)&sin->sin_addr.s_addr, dsthost, sizeof(dsthost));

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
    if (detail == LOW_DETAIL) {
      Snprintf(ipinfo, sizeof(ipinfo), "ttl=%d id=%hu iplen=%hu%s %s%s%s",
        ip->ip_ttl, (unsigned short) ntohs(ip->ip_id), (unsigned short) ntohs(ip->ip_len), fragnfo,
        ip->ip_hl==5?"":"ipopts={",
        ip->ip_hl==5?"":format_ip_options((u8*) ip + sizeof(struct ip), MIN((unsigned)(ip->ip_hl-5)*4,len-sizeof(struct ip))),
        ip->ip_hl==5?"":"}");
    } else if (detail == MEDIUM_DETAIL) {
      Snprintf(ipinfo, sizeof(ipinfo), "ttl=%d id=%hu proto=%d csum=0x%04x iplen=%hu%s %s%s%s",
        ip->ip_ttl, (unsigned short) ntohs(ip->ip_id),
        ip->ip_p, ntohs(ip->ip_sum),
        (unsigned short) ntohs(ip->ip_len), fragnfo,
        ip->ip_hl==5?"":"ipopts={",
        ip->ip_hl==5?"":format_ip_options((u8*) ip + sizeof(struct ip), MIN((unsigned)(ip->ip_hl-5)*4,len-sizeof(struct ip))),
        ip->ip_hl==5?"":"}");
    } else if (detail == HIGH_DETAIL) {
      Snprintf(ipinfo, sizeof(ipinfo), "ver=%d ihl=%d tos=0x%02x iplen=%hu id=%hu%s%s%s%s foff=%d%s ttl=%d proto=%d csum=0x%04x%s%s%s",
        ip->ip_v, ip->ip_hl,
        ip->ip_tos, (unsigned short) ntohs(ip->ip_len),
        (unsigned short) ntohs(ip->ip_id),
        (reserved_flag||dont_fragment||more_fragments) ? " flg=" : "",
        (reserved_flag)? "x" : "",
        (dont_fragment)? "D" : "",
        (more_fragments)? "M": "",
        frag_off, (more_fragments) ? "+" : "",
        ip->ip_ttl, ip->ip_p,
        ntohs(ip->ip_sum),
        ip->ip_hl==5?"":" ipopts={",
        ip->ip_hl==5?"":format_ip_options((u8*) ip + sizeof(struct ip), MIN((unsigned)(ip->ip_hl-5)*4,len-sizeof(struct ip))),
        ip->ip_hl==5?"":"}");
    }
  } else { /* IPv6 */
    const struct ip6_hdr *ip6;
    const struct sockaddr_in6 *sin6;

    ip6 = (struct ip6_hdr *) packet;

    /* Obtain IP source and destination info */
    sin6 = (struct sockaddr_in6 *) &hdr.src;
	inet_ntop(AF_INET6, (void *)sin6->sin6_addr.s6_addr, srchost, sizeof(srchost));
    sin6 = (struct sockaddr_in6 *) &hdr.dst;
	inet_ntop(AF_INET6, (void *)sin6->sin6_addr.s6_addr, dsthost, sizeof(dsthost));

    /* Obtain flow label and traffic class */
    u32 flow = ntohl(ip6->ip6_flow);
    u32 ip6_fl = flow & 0x000fffff;
    u32 ip6_tc = (flow & 0x0ff00000) >> 20;

    /* Create a string with information relevant to the specified level of detail */
    if (detail == LOW_DETAIL) {
      Snprintf(ipinfo, sizeof(ipinfo), "hopl=%d flow=%x payloadlen=%hu",
        ip6->ip6_hlim, ip6_fl, (unsigned short) ntohs(ip6->ip6_plen));
    } else if (detail == MEDIUM_DETAIL) {
      Snprintf(ipinfo, sizeof(ipinfo), "hopl=%d tclass=%d flow=%x payloadlen=%hu",
        ip6->ip6_hlim, ip6_tc, ip6_fl, (unsigned short) ntohs(ip6->ip6_plen));
    } else if (detail==HIGH_DETAIL) {
      Snprintf(ipinfo, sizeof(ipinfo), "ver=6, tclass=%x flow=%x payloadlen=%hu nh=%s hopl=%d ",
        ip6_tc, ip6_fl, (unsigned short) ntohs(ip6->ip6_plen),
        nexthdrtoa(ip6->ip6_nxt, 1), ip6->ip6_hlim);
    }
  }


  /* TCP INFORMATION ***********************************************************/
  if (hdr.proto == IPPROTO_TCP) {
    char tflags[10];
    char tcpinfo[64] = "";
    char buf[32];
    char tcpoptinfo[256] = "";
    tcp = (struct tcp_hdr *) data;

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
      tcp = (struct tcp_hdr *)((u8 *) tcp - frag_off); // ugly?

      /* TCP Flags */
      p = tflags;
      /* These are basically in tcpdump order */
      if (tcp->th_flags & TH_SYN)
        *p++ = 'S';
      if (tcp->th_flags & TH_FIN)
        *p++ = 'F';
      if (tcp->th_flags & TH_RST)
        *p++ = 'R';
      if (tcp->th_flags & TH_PUSH)
        *p++ = 'P';
      if (tcp->th_flags & TH_ACK) {
        *p++ = 'A';
        Snprintf(tcpinfo, sizeof(tcpinfo), " ack=%lu",
          (unsigned long) ntohl(tcp->th_ack));
      }
      if (tcp->th_flags & TH_URG)
        *p++ = 'U';
      if (tcp->th_flags & TH_ECE)
        *p++ = 'E'; /* rfc 2481/3168 */
      if (tcp->th_flags & TH_CWR)
        *p++ = 'C'; /* rfc 2481/3168 */
      *p++ = '\0';

      /* TCP Options */
      if ((u32) tcp->th_off * 4 > sizeof(struct tcp_hdr)) {
        if (datalen < (u32) tcp->th_off * 4 - frag_off) {
          Snprintf(tcpoptinfo, sizeof(tcpoptinfo), "option incomplete");
        } else {
          tcppacketoptinfo((u8*) tcp + sizeof(struct tcp_hdr),
            tcp->th_off*4 - sizeof(struct tcp_hdr),
            tcpoptinfo, sizeof(tcpoptinfo));
        }
      }

      /* Create a string with TCP information relevant to the specified level of detail */
      if (detail == LOW_DETAIL) { Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s %s %s %s",
          srchost, dsthost, tflags, ipinfo, tcpinfo, tcpoptinfo);
      } else if (detail == MEDIUM_DETAIL) {
        Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s ack=%lu win=%hu %s IP [%s]",
          srchost, dsthost, tflags,
          (unsigned long) ntohl(tcp->th_ack), (unsigned short) ntohs(tcp->th_win),
          tcpoptinfo, ipinfo);
      } else if (detail == HIGH_DETAIL) {
        if (datalen >= 12) { /* We have at least bytes 8-20 */
          Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:?? > %s:?? %s seq=%lu ack=%lu off=%d res=%d win=%hu csum=0x%04X urp=%hu%s%s] IP [%s]",
            srchost, dsthost, tflags,
            (unsigned long) ntohl(tcp->th_seq),
            (unsigned long) ntohl(tcp->th_ack),
            (u8)tcp->th_off, (u8)tcp->th_x2, (unsigned short) ntohs(tcp->th_win),
            ntohs(tcp->th_sum), (unsigned short) ntohs(tcp->th_urp),
            (tcpoptinfo[0]!='\0') ? " " : "",
            tcpoptinfo, ipinfo);
        } else { /* We only have bytes 8-16 */
          Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:?? > %s:?? %s ack=%lu win=%hu %s IP [%s]",
            srchost, dsthost, tflags,
            (unsigned long) ntohl(tcp->th_ack), (unsigned short) ntohs(tcp->th_win),
            tcpoptinfo, ipinfo);
        }
      }
    }
    /* For all cases after this, frag_off is necessarily 0 */

    /* CASE 3: where the IP packet is not a fragment but for some reason, we
     * don't have the entire TCP header, just part of it.*/
    else if (datalen < 20) {
      /* We know we have the first 8 bytes, so what's left? */
      /* We only have the first 64 bits: ports and seq number */
      if (datalen < 12) {
        Snprintf(tcpinfo, sizeof(tcpinfo), "TCP %s:%hu > %s:%hu ?? seq=%lu (incomplete) %s",
          srchost, (unsigned short) ntohs(tcp->th_sport), dsthost,
          (unsigned short) ntohs(tcp->th_dport), (unsigned long) ntohl(tcp->th_seq), ipinfo);
      }

      /* We only have the first 96 bits: ports, seq and ack number */
      else if (datalen < 16) {
        if (detail == LOW_DETAIL) { /* We don't print ACK in low detail */
          Snprintf(tcpinfo, sizeof(tcpinfo), "TCP %s:%hu > %s:%hu seq=%lu (incomplete), %s",
            srchost, (unsigned short) ntohs(tcp->th_sport), dsthost,
            (unsigned short) ntohs(tcp->th_dport), (unsigned long) ntohl(tcp->th_seq), ipinfo);
        } else {
          Snprintf(tcpinfo, sizeof(tcpinfo), "TCP [%s:%hu > %s:%hu seq=%lu ack=%lu (incomplete)] IP [%s]",
            srchost, (unsigned short) ntohs(tcp->th_sport), dsthost,
            (unsigned short) ntohs(tcp->th_dport), (unsigned long) ntohl(tcp->th_seq),
            (unsigned long) ntohl(tcp->th_ack), ipinfo);
        }
      }

      /* We are missing some part of the last 32 bits (checksum and urgent pointer) */
      else {
        p = tflags;
        /* These are basically in tcpdump order */
        if (tcp->th_flags & TH_SYN)
          *p++ = 'S';
        if (tcp->th_flags & TH_FIN)
          *p++ = 'F';
        if (tcp->th_flags & TH_RST)
          *p++ = 'R';
        if (tcp->th_flags & TH_PUSH)
          *p++ = 'P';
        if (tcp->th_flags & TH_ACK) {
          *p++ = 'A';
          Snprintf(buf, sizeof(buf), " ack=%lu",
            (unsigned long) ntohl(tcp->th_ack));
          strncat(tcpinfo, buf, sizeof(tcpinfo) - strlen(tcpinfo) - 1);
        }
        if (tcp->th_flags & TH_URG)
          *p++ = 'U';
        if (tcp->th_flags & TH_ECE)
          *p++ = 'E'; /* rfc 2481/3168 */
        if (tcp->th_flags & TH_CWR)
          *p++ = 'C'; /* rfc 2481/3168 */
        *p++ = '\0';


        /* Create a string with TCP information relevant to the specified level of detail */
        if (detail == LOW_DETAIL) { /* We don't print ACK in low detail */
          Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%hu > %s:%hu %s %s seq=%lu win=%hu (incomplete)",
            srchost, (unsigned short) ntohs(tcp->th_sport), dsthost, (unsigned short) ntohs(tcp->th_dport),
            tflags, ipinfo, (unsigned long) ntohl(tcp->th_seq),
            (unsigned short) ntohs(tcp->th_win));
        } else if (detail == MEDIUM_DETAIL) {
          Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%hu > %s:%hu %s seq=%lu ack=%lu win=%hu (incomplete)] IP [%s]",
            srchost, (unsigned short) ntohs(tcp->th_sport), dsthost, (unsigned short) ntohs(tcp->th_dport),
            tflags,  (unsigned long) ntohl(tcp->th_seq),
            (unsigned long) ntohl(tcp->th_ack),
            (unsigned short) ntohs(tcp->th_win), ipinfo);
        } else if (detail == HIGH_DETAIL) {
          Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%hu > %s:%hu %s seq=%lu ack=%lu off=%d res=%d win=%hu (incomplete)] IP [%s]",
            srchost, (unsigned short) ntohs(tcp->th_sport),
            dsthost, (unsigned short) ntohs(tcp->th_dport),
            tflags, (unsigned long) ntohl(tcp->th_seq),
            (unsigned long) ntohl(tcp->th_ack),
            (u8)tcp->th_off, (u8)tcp->th_x2, (unsigned short) ntohs(tcp->th_win),
            ipinfo);
        }
      }
    }

    /* CASE 4: where we (finally!) have a full 20 byte TCP header so we can
     * safely print all fields */
    else { /* if (datalen >= 20) */

      /* TCP Flags */
      p = tflags;
      /* These are basically in tcpdump order */
      if (tcp->th_flags & TH_SYN)
        *p++ = 'S';
      if (tcp->th_flags & TH_FIN)
        *p++ = 'F';
      if (tcp->th_flags & TH_RST)
        *p++ = 'R';
      if (tcp->th_flags & TH_PUSH)
        *p++ = 'P';
      if (tcp->th_flags & TH_ACK) {
        *p++ = 'A';
        Snprintf(buf, sizeof(buf), " ack=%lu",
            (unsigned long) ntohl(tcp->th_ack));
        strncat(tcpinfo, buf, sizeof(tcpinfo) - strlen(tcpinfo) - 1);
      }
      if (tcp->th_flags & TH_URG)
        *p++ = 'U';
      if (tcp->th_flags & TH_ECE)
        *p++ = 'E'; /* rfc 2481/3168 */
      if (tcp->th_flags & TH_CWR)
        *p++ = 'C'; /* rfc 2481/3168 */
      *p++ = '\0';

      /* TCP Options */
      if ((u32) tcp->th_off * 4 > sizeof(struct tcp_hdr)) {
        if (datalen < (unsigned int) tcp->th_off * 4) {
          Snprintf(tcpoptinfo, sizeof(tcpoptinfo), "option incomplete");
        } else {
          tcppacketoptinfo((u8*) tcp + sizeof(struct tcp_hdr),
            tcp->th_off*4 - sizeof(struct tcp_hdr),
            tcpoptinfo, sizeof(tcpoptinfo));
        }
      }

      /* Rest of header fields */
      if (detail == LOW_DETAIL) {
        Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%hu > %s:%hu %s %s seq=%lu win=%hu %s",
          srchost, (unsigned short) ntohs(tcp->th_sport), dsthost, (unsigned short) ntohs(tcp->th_dport),
          tflags, ipinfo, (unsigned long) ntohl(tcp->th_seq),
          (unsigned short) ntohs(tcp->th_win), tcpoptinfo);
      } else if (detail == MEDIUM_DETAIL) {
        Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%hu > %s:%hu %s seq=%lu win=%hu csum=0x%04X%s%s] IP [%s]",
          srchost, (unsigned short) ntohs(tcp->th_sport), dsthost, (unsigned short) ntohs(tcp->th_dport),
          tflags, (unsigned long) ntohl(tcp->th_seq),
          (unsigned short) ntohs(tcp->th_win),  (unsigned short) ntohs(tcp->th_sum),
          (tcpoptinfo[0]!='\0') ? " " : "",
          tcpoptinfo, ipinfo);
      } else if (detail == HIGH_DETAIL) {
        Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%hu > %s:%hu %s seq=%lu ack=%lu off=%d res=%d win=%hu csum=0x%04X urp=%hu%s%s] IP [%s]",
          srchost, (unsigned short) ntohs(tcp->th_sport),
          dsthost, (unsigned short) ntohs(tcp->th_dport),
          tflags, (unsigned long) ntohl(tcp->th_seq),
          (unsigned long) ntohl(tcp->th_ack),
          (u8)tcp->th_off, (u8)tcp->th_x2, (unsigned short) ntohs(tcp->th_win),
          ntohs(tcp->th_sum), (unsigned short) ntohs(tcp->th_urp),
          (tcpoptinfo[0]!='\0') ? " " : "",
          tcpoptinfo, ipinfo);
      }
    }

    /* UDP INFORMATION ***********************************************************/
  } else if (hdr.proto == IPPROTO_UDP && frag_off) {
    Snprintf(protoinfo, sizeof(protoinfo), "UDP %s:?? > %s:?? fragment %s (incomplete)",
      srchost, dsthost, ipinfo);
  } else if (hdr.proto == IPPROTO_UDP) {
    udp = (struct udp_hdr *) data;
    /* TODO: See if we can segfault if we receive a fragmented packet whose IP packet does not say a thing about fragmentation */

    if (detail == LOW_DETAIL) {
      Snprintf(protoinfo, sizeof(protoinfo), "UDP %s:%hu > %s:%hu %s",
          srchost, (unsigned short) ntohs(udp->uh_sport), dsthost, (unsigned short) ntohs(udp->uh_dport),
          ipinfo);
    } else if (detail == MEDIUM_DETAIL) {
      Snprintf(protoinfo, sizeof(protoinfo), "UDP [%s:%hu > %s:%hu csum=0x%04X] IP [%s]",
        srchost, (unsigned short) ntohs(udp->uh_sport), dsthost, (unsigned short) ntohs(udp->uh_dport), ntohs(udp->uh_sum),
        ipinfo);
    } else if (detail == HIGH_DETAIL) {
      Snprintf(protoinfo, sizeof(protoinfo), "UDP [%s:%hu > %s:%hu len=%hu csum=0x%04X] IP [%s]",
        srchost, (unsigned short) ntohs(udp->uh_sport), dsthost, (unsigned short) ntohs(udp->uh_dport),
        (unsigned short) ntohs(udp->uh_ulen), ntohs(udp->uh_sum),
        ipinfo);
    }

    /* SCTP INFORMATION **********************************************************/
  } else if (hdr.proto == IPPROTO_SCTP && frag_off) {
    Snprintf(protoinfo, sizeof(protoinfo), "SCTP %s:?? > %s:?? fragment %s (incomplete)",
      srchost, dsthost, ipinfo);
  } else if (hdr.proto == IPPROTO_SCTP) {
    sctp = (struct sctp_hdr *) data;

    if (detail == LOW_DETAIL) {
      Snprintf(protoinfo, sizeof(protoinfo), "SCTP %s:%hu > %s:%hu %s",
        srchost, (unsigned short) ntohs(sctp->sh_sport), dsthost, (unsigned short) ntohs(sctp->sh_dport),
        ipinfo);
    } else if (detail == MEDIUM_DETAIL) {
      Snprintf(protoinfo, sizeof(protoinfo), "SCTP [%s:%hu > %s:%hu csum=0x%08x] IP [%s]",
        srchost, (unsigned short) ntohs(sctp->sh_sport), dsthost, (unsigned short) ntohs(sctp->sh_dport), ntohl(sctp->sh_sum),
        ipinfo);
    } else if (detail == HIGH_DETAIL) {
      Snprintf(protoinfo, sizeof(protoinfo), "SCTP [%s:%hu > %s:%hu vtag=%lu csum=0x%08x] IP [%s]",
        srchost, (unsigned short) ntohs(sctp->sh_sport), dsthost, (unsigned short) ntohs(sctp->sh_dport),
        (unsigned long) ntohl(sctp->sh_vtag), ntohl(sctp->sh_sum),
        ipinfo);
    }

    /* ICMP INFORMATION **********************************************************/
  } else if (hdr.proto == IPPROTO_ICMP && frag_off) {
    Snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s fragment %s (incomplete)",
      srchost, dsthost, ipinfo);
  } else if (hdr.proto == IPPROTO_ICMP) {
    struct ip *ip2;       /* Points to the IP datagram carried by some ICMP messages */
    char *ip2dst;         /* Dest IP in caried IP datagram                   */
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
    } *icmpredir = NULL;
    struct icmp_router{
      u8 type;
      u8 code;
      u16 checksum;
      u8 addrs;
      u8 addrlen;
      u16 lifetime;
    } *icmprouter = NULL;
    struct icmp_param{
      u8 type;
      u8 code;
      u16 checksum;
      u8 pnt;
      u8 unused;
      u16 unused2;
    } *icmpparam = NULL;
    struct icmp_tstamp{
      u8 type;
      u8 code;
      u16 checksum;
      u16 id;
      u16 seq;
      u32 orig;
      u32 recv;
      u32 trans;
    } *icmptstamp = NULL;
    struct icmp_amask{
      u8 type;
      u8 code;
      u16 checksum;
      u16 id;
      u16 seq;
      u32 mask;
    } *icmpmask = NULL;

    /* Compute the ICMP minimum length. */
    unsigned pktlen = 8;

    /* We need the ICMP packet to be at least 8 bytes long */
    if (pktlen > datalen)
      goto icmpbad;

    ping = (struct ppkt *) data;
    icmppkt = (struct icmp_packet *) data;

    switch(icmppkt->type) {
      /* Echo Reply **************************/
      case 0:
        strcpy(icmptype, "Echo reply");
        Snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu", (unsigned short) ntohs(ping->id), (unsigned short) ntohs(ping->seq));
        break;

        /* Destination Unreachable *************/
      case 3:
        /* Point to the start of the original datagram */
        ip2 = (struct ip *) (data + 8);

        /* Check we have a full IP datagram included in the ICMP message */
        pktlen += MAX( (ip2->ip_hl * 4), 20);
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
        if ((ip2->ip_v != 4) || ((ip2->ip_hl * 4) < 20) || ((ip2->ip_hl * 4) > 60)) {
          Snprintf(icmptype, sizeof icmptype, "Destination unreachable (bogus original datagram)");
          goto icmpbad;
        } else {
          /* We have the original datagram + the first 8 bytes of the
           * transport layer header */
          if (pktlen + 8 < datalen) {
            tcp = (struct tcp_hdr *) ((char *) ip2 + (ip2->ip_hl * 4));
            udp = (struct udp_hdr *) ((char *) ip2 + (ip2->ip_hl * 4));
            sctp = (struct sctp_hdr *) ((char *) ip2 + (ip2->ip_hl * 4));
          }
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
            if (pktlen + 8 < datalen) {
              if (ip2->ip_p == IPPROTO_UDP && udp)
                Snprintf(icmptype, sizeof icmptype, "Port %hu unreachable", (unsigned short) ntohs(udp->uh_dport));
              else if (ip2->ip_p == IPPROTO_TCP && tcp)
                Snprintf(icmptype, sizeof icmptype, "Port %hu unreachable", (unsigned short) ntohs(tcp->th_dport));
              else if (ip2->ip_p == IPPROTO_SCTP && sctp)
                Snprintf(icmptype, sizeof icmptype, "Port %hu unreachable", (unsigned short) ntohs(sctp->sh_dport));
              else
                Snprintf(icmptype, sizeof icmptype, "Port unreachable (unknown protocol %u)", ip2->ip_p);
            }
            else
              strcpy(icmptype, "Port unreachable");
            break;

          case 4:
            strcpy(icmptype, "Fragmentation required");
            Snprintf(icmpfields, sizeof(icmpfields), "Next-Hop-MTU=%d", icmppkt->data[2]<<8 | icmppkt->data[3]);
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
        else
          strcpy(icmptype, "Redirect (unknown code)");
        icmpredir = (struct icmp_redir *) icmppkt;
        inet_ntop(AF_INET, &icmpredir->addr, auxbuff, sizeof(auxbuff));
        Snprintf(icmpfields, sizeof(icmpfields), "addr=%s", auxbuff);
        break;

        /* Echo Request ************************/
      case 8:
        strcpy(icmptype, "Echo request");
        Snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu", (unsigned short) ntohs(ping->id), (unsigned short) ntohs(ping->seq));
        break;

        /* Router Advertisement ****************/
      case 9:
        if (icmppkt->code == 16)
          strcpy(icmptype, "Router advertisement (Mobile Agent Only)");
        else
          strcpy(icmptype, "Router advertisement");
        icmprouter = (struct icmp_router *) icmppkt;
        Snprintf(icmpfields, sizeof(icmpfields), "addrs=%u addrlen=%u lifetime=%hu",
          icmprouter->addrs,
          icmprouter->addrlen,
          (unsigned short) ntohs(icmprouter->lifetime));
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
        else
          strcpy(icmptype, "TTL exceeded (unknown code)");
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
        icmpparam = (struct icmp_param *) icmppkt;
        Snprintf(icmpfields, sizeof(icmpfields), "pointer=%d", icmpparam->pnt);
        break;

        /* Timestamp Request/Reply *************/
      case 13:
      case 14:
        Snprintf(icmptype, sizeof(icmptype), "Timestamp %s", (icmppkt->type == 13)? "request" : "reply");
        icmptstamp = (struct icmp_tstamp *) icmppkt;
        Snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu orig=%lu recv=%lu trans=%lu",
          (unsigned short) ntohs(icmptstamp->id), (unsigned short) ntohs(icmptstamp->seq),
          (unsigned long) ntohl(icmptstamp->orig),
          (unsigned long) ntohl(icmptstamp->recv),
          (unsigned long) ntohl(icmptstamp->trans));
        break;

        /* Information Request *****************/
      case 15:
        strcpy(icmptype, "Information request");
        Snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu", (unsigned short) ntohs(ping->id), (unsigned short) ntohs(ping->seq));
        break;

        /* Information Reply *******************/
      case 16:
        strcpy(icmptype, "Information reply");
        Snprintf(icmpfields, sizeof(icmpfields), "id=%hu seq=%hu", (unsigned short) ntohs(ping->id), (unsigned short) ntohs(ping->seq));
        break;

        /* Netmask Request/Reply ***************/
      case 17:
      case 18:
        Snprintf(icmptype, sizeof(icmptype), "Address mask %s", (icmppkt->type == 17)? "request" : "reply");
        icmpmask = (struct icmp_amask *) icmppkt;
        inet_ntop(AF_INET, &icmpmask->mask, auxbuff, sizeof(auxbuff));
        Snprintf(icmpfields, sizeof(icmpfields), "id=%u seq=%u mask=%s",
            (unsigned short) ntohs(ping->id), (unsigned short) ntohs(ping->seq), auxbuff);
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
      if (ping) {
        /* We still have this information */
        Snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s %s (type=%d/code=%d) %s",
            srchost, dsthost, icmptype, ping->type, ping->code, ipinfo);
      } else {
        Snprintf(protoinfo, sizeof(protoinfo), "ICMP %s > %s [??] %s",
            srchost, dsthost, ipinfo);
      }
    } else {
      if (ping)
        sprintf(icmpinfo,"type=%d/code=%d", ping->type, ping->code);
      else
        strncpy(icmpinfo,"type=?/code=?", sizeof(icmpinfo));

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


#ifdef HAVE_LINUX_RTNETLINK_H
/* Fill in a sockaddr_storage given an address family and raw address. */
static int set_sockaddr(struct sockaddr_storage *ss, int af, void *data) {
  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;

  ss->ss_family = af;
  if (af == AF_INET) {
    sin = (struct sockaddr_in *) ss;
    memcpy(&sin->sin_addr.s_addr, data, IP_ADDR_LEN);
  } else if (af == AF_INET6) {
    sin6 = (struct sockaddr_in6 *) ss;
    memcpy(sin6->sin6_addr.s6_addr, data, IP6_ADDR_LEN);
  } else {
    return -1;
  }

  return 0;
}

/* Add rtattrs to a netlink message specifying a source or destination address.
   rta_type must be RTA_SRC or RTA_DST. This function adds either 1 or 2
   rtattrs: it always adds either an RTA_SRC or RTA_DST, depending on rta_type.
   If ifindex is not 0, it is the index of the interface to use. The function
   adds either RTA_OIF if rta_type is RTA_DST, and either of ifindex and
   sin6_scope_id is nonzero. */
static void add_rtattr_addr(struct nlmsghdr *nlmsg,
                            struct rtattr **rtattr, unsigned int *len,
                            unsigned char rta_type,
                            const struct sockaddr_storage *ss,
                            int ifindex) {
  struct rtmsg *rtmsg;
  const void *addr;
  size_t addrlen;

  assert(rta_type == RTA_SRC || rta_type == RTA_DST);

  if (rta_type == RTA_SRC) {
    /* Ignore the interface specification if we are setting an RTA_SRC attribute
       (it may still get set by the scope_id below). */
    ifindex = 0;
  }

  if (ss->ss_family == AF_INET) {
    addr = &((struct sockaddr_in *) ss)->sin_addr.s_addr;
    addrlen = IP_ADDR_LEN;
  } else if (ss->ss_family == AF_INET6) {
    const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ss;

    addr = sin6->sin6_addr.s6_addr;
    addrlen = IP6_ADDR_LEN;
    if (ifindex == 0)
      ifindex = sin6->sin6_scope_id;
  } else {
    netutil_fatal("%s: unknown address family %d", __func__, ss->ss_family);
  }

  rtmsg = (struct rtmsg *) (nlmsg + 1);
  if (rta_type == RTA_SRC)
    rtmsg->rtm_src_len = addrlen * 8;
  else
    rtmsg->rtm_dst_len = addrlen * 8;

  /* Add an rtattr for the address. */
  (*rtattr)->rta_type = rta_type;
  (*rtattr)->rta_len = RTA_LENGTH(addrlen);
  assert(RTA_OK(*rtattr, *len));
  memcpy(RTA_DATA(*rtattr), addr, addrlen);
  nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + (*rtattr)->rta_len;
  *rtattr = RTA_NEXT(*rtattr, *len);

  /* Specific interface (sin6_scope_id) requested? */
  if (ifindex > 0) {
    /* Add an rtattr for the interface. */
    if (rta_type == RTA_SRC)
      (*rtattr)->rta_type = RTA_IIF;
    else
      (*rtattr)->rta_type = RTA_OIF;
    (*rtattr)->rta_len = RTA_LENGTH(sizeof(uint32_t));
    assert(RTA_OK(*rtattr, *len));
    *(uint32_t *) RTA_DATA(*rtattr) = ifindex;
    nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + (*rtattr)->rta_len;
    *rtattr = RTA_NEXT(*rtattr, *len);
  }
}

/* Does route_dst using the Linux-specific rtnetlink interface. See rtnetlink(3)
   and rtnetlink(7). */
static int route_dst_netlink(const struct sockaddr_storage *dst,
                             struct route_nfo *rnfo, const char *device,
                             const struct sockaddr_storage *spoofss) {
  struct sockaddr_nl snl;
  struct msghdr msg;
  struct iovec iov;
  struct nlmsghdr *nlmsg;
  struct rtmsg *rtmsg;
  struct rtattr *rtattr;
  int intf_index;
  unsigned char buf[512];
  unsigned int len;
  int fd, rc;

  fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd == -1)
    netutil_fatal("%s: cannot create AF_NETLINK socket: %s", __func__, strerror(errno));

  memset(&snl, 0, sizeof(snl));
  snl.nl_family = AF_NETLINK;

  rc = bind(fd, (struct sockaddr *) &snl, sizeof(snl));
  if (rc == -1)
    netutil_fatal("%s: cannot bind AF_NETLINK socket: %s", __func__, strerror(errno));

  struct interface_info *ii;
  ii = NULL;
  intf_index = 0;
  if (device != NULL && device[0] != '\0') {
    ii = getInterfaceByName(device, dst->ss_family);
    if (ii == NULL)
      netutil_fatal("Could not find interface %s which was specified by -e", device);
    intf_index = ii->ifindex;
  }

  memset(buf, 0, sizeof(buf));

  nlmsg = (struct nlmsghdr *) buf;

  nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(*rtmsg));
  assert(nlmsg->nlmsg_len <= sizeof(buf));
  nlmsg->nlmsg_flags = NLM_F_REQUEST;
  nlmsg->nlmsg_type = RTM_GETROUTE;

  rtmsg = (struct rtmsg *) (nlmsg + 1);
  rtmsg->rtm_family = dst->ss_family;

  rtattr = RTM_RTA(rtmsg);
  len = sizeof(buf) - ((unsigned char *) RTM_RTA(rtmsg) - buf);

  /* Add rtattrs for destination address and interface. */
  add_rtattr_addr(nlmsg, &rtattr, &len, RTA_DST, dst, intf_index);
  if (spoofss != NULL) {
    /* Add rtattrs for source address and interface. */
    add_rtattr_addr(nlmsg, &rtattr, &len, RTA_SRC, spoofss, intf_index);
  }

  iov.iov_base = nlmsg;
  iov.iov_len = nlmsg->nlmsg_len;

  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &snl;
  msg.msg_namelen = sizeof(snl);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  rc = sendmsg(fd, &msg, 0);
  if (rc == -1)
    netutil_fatal("%s: cannot sendmsg: %s", __func__, strerror(errno));

  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);

  len = recvmsg(fd, &msg, 0);
  if (len <= 0)
    netutil_fatal("%s: cannot recvmsg: %s", __func__, strerror(errno));

  close(fd);

  if (nlmsg->nlmsg_len < sizeof(*nlmsg) || (unsigned int) len < NLMSG_LENGTH(sizeof(*nlmsg)))
    netutil_fatal("%s: wrong size reply in recvmsg", __func__);
  len -= NLMSG_LENGTH(sizeof(*nlmsg));

  /* See rtnetlink(7). Anything matching this route is actually unroutable. */
  if (rtmsg->rtm_type == RTN_UNREACHABLE || rtmsg->rtm_type == RTN_UNSPEC
    || rtmsg->rtm_type == RTN_BLACKHOLE || rtmsg->rtm_type == RTN_PROHIBIT)
    return 0;

  /* Default values to be possibly overridden. */
  rnfo->direct_connect = 1;
  rnfo->nexthop.ss_family = AF_UNSPEC;
  rnfo->srcaddr.ss_family = AF_UNSPEC;
  if (spoofss != NULL)
    rnfo->srcaddr = *spoofss;

  for (rtattr = RTM_RTA(rtmsg); RTA_OK(rtattr, len); rtattr = RTA_NEXT(rtattr, len)) {
    if (rtattr->rta_type == RTA_GATEWAY) {
      rc = set_sockaddr(&rnfo->nexthop, dst->ss_family, RTA_DATA(rtattr));
      assert(rc != -1);
      /* Don't consider it directly connected if nexthop != dst. */
      if (!sockaddr_storage_equal(dst, &rnfo->nexthop))
        rnfo->direct_connect = 0;
    } else if (rtattr->rta_type == RTA_OIF && ii == NULL) {
      char namebuf[IFNAMSIZ];
      char *p;
      int intf_index;

      intf_index = *(int *) RTA_DATA(rtattr);
      p = if_indextoname(intf_index, namebuf);
      if (p == NULL)
        netutil_fatal("%s: if_indextoname(%d) failed: %d (%s)", __func__, intf_index, errno, strerror(errno));
      ii = getInterfaceByName(namebuf, dst->ss_family);
      if (ii == NULL)
        ii = getInterfaceByName(namebuf, AF_UNSPEC);
      if (ii == NULL)
        netutil_fatal("%s: can't find interface \"%s\"", __func__, namebuf);
    } else if (rtattr->rta_type == RTA_PREFSRC && rnfo->srcaddr.ss_family == AF_UNSPEC) {
      rc = set_sockaddr(&rnfo->srcaddr, dst->ss_family, RTA_DATA(rtattr));
      assert(rc != -1);
    }
  }

  if (ii != NULL) {
    rnfo->ii = *ii;
    return 1;
  } else {
    return 0;
  }
}

#else

static struct interface_info *find_loopback_iface(struct interface_info *ifaces,
  int numifaces) {
  int i;

  for (i = 0; i < numifaces; i++) {
    if (ifaces[i].device_type == devt_loopback)
      return &ifaces[i];
  }

  return NULL;
}

/* Get the source address for routing to dst by creating a socket and asking the
   operating system for the local address. */
static int get_srcaddr(const struct sockaddr_storage *dst,
  struct sockaddr_storage *src)
{
  static const unsigned short DUMMY_PORT = 1234;
  struct sockaddr_storage dst_dummy;
  size_t dst_dummy_len;
  socklen_t len;
  int fd, rc;

  fd = socket(dst->ss_family, SOCK_DGRAM, 0);
  if (fd == -1)
    netutil_fatal("%s: can't create socket: %s", __func__, socket_strerror(socket_errno()));

  dst_dummy = *dst;
  if (dst_dummy.ss_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *) &dst_dummy;
    sin->sin_port = htons(DUMMY_PORT);
    dst_dummy_len = sizeof(*sin);
  } else if (dst_dummy.ss_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &dst_dummy;
    sin6->sin6_port = htons(DUMMY_PORT);
    dst_dummy_len = sizeof(*sin6);
  } else {
    goto bail;
  }

  rc = connect(fd, (struct sockaddr *) &dst_dummy, dst_dummy_len);
  if (rc == -1) {
    netutil_error("%s: can't connect socket: %s", __func__, socket_strerror(socket_errno()));
    if (dst->ss_family == AF_INET6) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &dst_dummy;
      if (sin6->sin6_scope_id == 0)
        netutil_error("Do you need an IPv6 zone ID suffix (e.g. %%eth0 or %%1)?");
    }
    goto bail;
  }

  len = sizeof(*src);
  rc = getsockname(fd, (struct sockaddr *) src, &len);
  if (rc == -1)
    netutil_fatal("%s: can't getsockname: %s", __func__, socket_strerror(socket_errno()));

  close(fd);
  return 0;

bail:
  close(fd);
  return -1;
}

static char *lookup_ifindex(unsigned int index, int af, char *namebuf, size_t len) {
  intf_t *it;
  struct intf_entry entry;
  int rc;

  it = intf_open();
  assert(it != NULL);
  entry.intf_len = sizeof(entry);
  rc = intf_get_index(it, &entry, af, index);
  intf_close(it);
  if (rc == -1)
    return NULL;

  Strncpy(namebuf, entry.intf_name, len);
  return namebuf;
}

static int route_dst_generic(const struct sockaddr_storage *dst,
                             struct route_nfo *rnfo, const char *device,
                             const struct sockaddr_storage *spoofss) {
  struct interface_info *ifaces;
  struct interface_info *iface;
  int numifaces = 0;
  struct sys_route *routes;
  int numroutes = 0;
  int i;
  char namebuf[32];
  char errstr[256];
  errstr[0]='\0';

  if (!dst)
    netutil_fatal("%s passed a NULL dst address", __func__);

  if(spoofss!=NULL){
    /* Throughout the rest of this function we only change rnfo->srcaddr if the source isn't spoofed */
    memcpy(&rnfo->srcaddr, spoofss, sizeof(rnfo->srcaddr));
    /* The device corresponding to this spoofed address should already have been set elsewhere. */
    assert(device!=NULL && device[0]!='\0');
  }

  if (device == NULL || device[0] == '\0') {
    /* Check if there is an interface scope on the address which we must use. */
    if (dst->ss_family == AF_INET6) {
      const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) dst;
      if (sin6->sin6_scope_id > 0) {
        device = lookup_ifindex(sin6->sin6_scope_id, sin6->sin6_family, namebuf, sizeof(namebuf));
        if (device == NULL) {
          netutil_error("Could not find interface with index %u", (unsigned int) sin6->sin6_scope_id);
          return 0;
        }
      }
    }
  }

  if (device!=NULL && device[0]!='\0'){
    iface = getInterfaceByName(device, dst->ss_family);
    if (!iface)
      netutil_fatal("Could not find interface %s", device);
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

    if (!sockaddr_equal(dst, &ifaces[i].addr))
      continue;

    if (ifaces[i].device_type == devt_loopback)
      loopback = &ifaces[i];
    else
      loopback = find_loopback_iface(ifaces, numifaces);
    if (loopback == NULL)
      /* Hmmm ... no localhost -- move on to the routing table. */
      break;

    if (iface != NULL && strcmp(loopback->devname, iface->devname) != 0)
      continue;

    if (iface == NULL && !loopback->device_up)
      continue;

    rnfo->ii = *loopback;
    rnfo->direct_connect = 1;
    /* But the source address we want to use is the target address. */
    if (!spoofss) {
      if (get_srcaddr(dst, &rnfo->srcaddr) == -1)
        rnfo->srcaddr = rnfo->ii.addr;
    }

    return 1;
  }

  /* Go through the routing table and take the first match. getsysroutes sorts
     so more-specific routes come first. */
  for (i = 0; i < numroutes; i++) {
    if (!sockaddr_equal_netmask(dst, &routes[i].dest, routes[i].netmask_bits))
      continue;
    /* Ignore routes that aren't on the device we specified. */
    if (iface != NULL && strcmp(routes[i].device->devname, iface->devname) != 0)
      continue;

    if (iface == NULL && !routes[i].device->device_up)
      continue;

    rnfo->ii = *routes[i].device;
    /* At this point we don't whether this route is direct or indirect ("G" flag
       in netstat). We guess that a route is direct when the gateway address is
       0.0.0.0 or ::, when it exactly matches the interface address, or when it
       exactly matches the destination address. */
    rnfo->direct_connect = (sockaddr_equal_zero(&routes[i].gw) ||
      sockaddr_equal(&routes[i].gw, &routes[i].device->addr) ||
      sockaddr_equal(&routes[i].gw, dst));
    if (!spoofss) {
      if (get_srcaddr(dst, &rnfo->srcaddr) == -1)
        rnfo->srcaddr = rnfo->ii.addr;
    }
    rnfo->nexthop = routes[i].gw;

    return 1;
  }

  /* No match on routes. Try interfaces directly. */
  for (i = 0; i < numifaces; i++) {
    if (!sockaddr_equal_netmask(dst, &ifaces[i].addr, ifaces[i].netmask_bits))
      continue;
    if (iface != NULL && strcmp(ifaces[i].devname, iface->devname) != 0)
      continue;

    if (iface == NULL && !ifaces[i].device_up)
      continue;

    rnfo->ii = ifaces[i];
    rnfo->direct_connect = 1;
    if (!spoofss) {
      if (get_srcaddr(dst, &rnfo->srcaddr) == -1)
        rnfo->srcaddr = rnfo->ii.addr;
    }

    return 1;
  }

  return 0;
}
#endif

/* Takes a destination address (dst) and tries to determine the
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
              const char *device, const struct sockaddr_storage *spoofss) {
#ifdef HAVE_LINUX_RTNETLINK_H
  return route_dst_netlink(dst, rnfo, device, spoofss);
#else
  return route_dst_generic(dst, rnfo, device, spoofss);
#endif
}

/* Wrapper for system function sendto(), which retries a few times when
 * the call fails. It also prints informational messages about the
 * errors encountered. It returns the number of bytes sent or -1 in
 * case of error. */
int Sendto(const char *functionname, int sd,
                  const unsigned char *packet, int len, unsigned int flags,
                  struct sockaddr *to, int tolen) {

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
              functionname, sd, len, inet_ntop_ez((struct sockaddr_storage *) to, sizeof(struct sockaddr_storage)), tolen,
              strerror(err));
        netutil_error("Offending packet: %s", ippackethdrinfo(packet, len, LOW_DETAIL));
        if (numerrors == 10) {
          netutil_error("Omitting future %s error messages now that %d have been shown.  Use -d2 if you really want to see them.", __func__, numerrors);
        }
      }
#if WIN32
      return -1;
#else
      if (retries > 2)
        return -1;
      /* For these enumerated errors, we sleep and try again. */
      if (!(err == ENOBUFS || err == ENOMEM))
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
int send_ip_packet_eth(const struct eth_nfo *eth, const u8 *packet, unsigned int packetlen) {
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
int send_ip_packet_sd(int sd, const struct sockaddr_in *dst,
  const u8 *packet, unsigned int packetlen) {
  struct sockaddr_in sock;
  struct ip *ip = (struct ip *) packet;
  struct tcp_hdr *tcp;
  struct udp_hdr *udp;
  int res;

  assert(sd >= 0);
  sock = *dst;

  /* It is bogus that I need the address and port info when sending a RAW IP
     packet, but it doesn't seem to work w/o them */
  if (packetlen >= 20) {
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
#if (defined(FREEBSD) && (__FreeBSD_version < 1100030)) || BSDI || NETBSD || DEC || MACOSX
  ip->ip_len = ntohs(ip->ip_len);
  ip->ip_off = ntohs(ip->ip_off);
#endif

  res = Sendto("send_ip_packet_sd", sd, packet, packetlen, 0,
               (struct sockaddr *) &sock,
               (int) sizeof(struct sockaddr_in));

  /* Undo the byte order switching. */
#if (defined(FREEBSD) && (__FreeBSD_version < 1100030)) || BSDI || NETBSD || DEC || MACOSX
  ip->ip_len = htons(ip->ip_len);
  ip->ip_off = htons(ip->ip_off);
#endif

  return res;
}



/* Sends the supplied pre-built IPv4 packet. The packet is sent through
 * the raw socket "sd" if "eth" is NULL. Otherwise, it gets sent at raw
 * ethernet level. */
int send_ip_packet_eth_or_sd(int sd, const struct eth_nfo *eth,
  const struct sockaddr_in *dst,
  const u8 *packet, unsigned int packetlen) {
  if(eth)
    return send_ip_packet_eth(eth, packet, packetlen);
  else
    return send_ip_packet_sd(sd, dst, packet, packetlen);
}



/* Create and send all fragments of a pre-built IPv4 packet
 * Minimal MTU for IPv4 is 68 and maximal IPv4 header size is 60
 * which gives us a right to cut TCP header after 8th byte
 * (shouldn't we inflate the header to 60 bytes too?) */
int send_frag_ip_packet(int sd, const struct eth_nfo *eth,
  const struct sockaddr_in *dst,
  const u8 *packet, unsigned int packetlen, u32 mtu) {
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
    return send_ip_packet_eth_or_sd(sd, eth, dst, packet, packetlen);
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
    res = send_ip_packet_eth_or_sd(sd, eth, dst, fpacket, ntohs(ip->ip_len));
    if (res == -1)
      break;
  }
  free(fpacket);
  return res;
}

/* There are three ways to send a raw IPv6 packet.

   send_ipv6_eth works when the device is Ethernet. (Unfortunately IPv6-in-IPv4
   tunnels are not.) We can control all header fields and extension headers.

   send_ipv6_ipproto_raw must be used when IPPROTO_RAW sockets include the IP
   header, like IP_HDRINCL for IPv4. This is non-standard but is the case on
   Linux. (On other platforms, IPPROTO_RAW has no special meaning and just
   stands for protocol 255.) We can control all header fields and extension
   headers. This method uses only one raw socket for all sends.

   send_ipv6_ip must be used when IPPROTO_RAW sockets do not include the IP
   header. Through standard function calls we can control all header fields
   except for the flow label. This method needs one raw socket for every
   protocol. (More precisely, one socket per distinct Next Header value.)
*/

/* Send an IPv6 packet over an Ethernet handle. */
static int send_ipv6_eth(const struct eth_nfo *eth, const u8 *packet, unsigned int packetlen) {
  eth_t *ethsd;
  struct eth_hdr *eth_frame;
  u8 *copy;
  int res;

  copy = (u8 *) safe_malloc(packetlen + sizeof(*eth_frame));
  memcpy(copy + sizeof(*eth_frame), packet, packetlen);
  eth_frame = (struct eth_hdr *) copy;
  eth_pack_hdr(eth_frame, eth->dstmac, eth->srcmac, ETH_TYPE_IPV6);
  if (!eth->ethsd) {
    ethsd = eth_open_cached(eth->devname);
    if (!ethsd)
      netutil_fatal("%s: Failed to open ethernet device (%s)", __func__, eth->devname);
  } else {
    ethsd = eth->ethsd;
  }
  res = eth_send(ethsd, eth_frame, sizeof(*eth_frame) + packetlen);
  /* No need to close ethsd due to caching */
  free(eth_frame);

  return res;
}

#if HAVE_IPV6_IPPROTO_RAW

/* Send an IPv6 packet over a raw socket, on platforms where IPPROTO_RAW implies
   IP_HDRINCL-like behavior. */
static int send_ipv6_ipproto_raw(const struct sockaddr_in6 *dst,
  const unsigned char *packet, unsigned int packetlen) {
  int sd, n;

  sd = -1;
  n = -1;

  sd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
  if (sd == -1) {
    perror("socket");
    goto bail;
  }

  n = Sendto(__func__, sd, packet, packetlen, 0, (struct sockaddr *) dst, sizeof(*dst));

bail:
  if (sd != -1)
    close(sd);

  return n;
}

#elif !WIN32

/* Add an ancillary cmsghdr data block to the list of blocks in a msghdr.
   The list is stored in msg->msg_control, which is dynamically allocated
   and reallocated as needed. It must be freed after this function returns.
   msg->msg_controllen is also modified by this function. Returns -1 in case of
   error or 0 otherwise. */
static int add_ancillary(struct msghdr *msg, int level, int type,
  const void *data, size_t len)
{
  struct cmsghdr *cm;
  void *p;

  p = realloc(msg->msg_control, msg->msg_controllen + CMSG_SPACE(len));
  if (p == NULL)
    return -1;
  msg->msg_control = p;

  cm = (struct cmsghdr *) ((char *) msg->msg_control + msg->msg_controllen);
  msg->msg_controllen += CMSG_SPACE(len);

  cm->cmsg_len = CMSG_LEN(len);
  cm->cmsg_level = level;
  cm->cmsg_type = type;

  memcpy(CMSG_DATA(cm), data, len);

  return 0;
}

static int exthdr_type_to_cmsg_type(uint8_t type) {
  switch (type) {
  /* These are the only extension headers we can set directly through a
     msghdr. */
  case 0:
    return IPV6_HOPOPTS;
  case 43:
    return IPV6_RTHDR;
  case 60:
    return IPV6_DSTOPTS;
  default:
    return -1;
  }
}

static const unsigned char *add_exthdr_ancillary(struct msghdr *msg,
  const unsigned char *p, size_t len, unsigned char *proto) {
  unsigned char nxt;
  size_t extlen;
  int cmsg_type;

  cmsg_type = exthdr_type_to_cmsg_type(*proto);
  if (cmsg_type == -1)
    return NULL;

  if (len < 2)
    return NULL;
  nxt = *p;
  extlen = (*(p + 1) + 1) * 8;
  if (len < extlen)
    return NULL;
  if (add_ancillary(msg, IPPROTO_IPV6, cmsg_type, p, extlen) == -1)
    return NULL;

  *proto = nxt;

  return p + extlen;
}

/* Send an IPv6 packet over a raw socket. This function can control all header
   fields except the flow label (and the payload length can only be controlled
   indirectly through the length of the payload).

   For most extension header types, we initialize the socket with the given
   protocol, which causes the Next Header field to match when the packet is set.
   This allows stuffing arbitrary data into extension headers. However, for a
   few well-known headers (like Destination and Routing options), this fails
   with EPROTOTYPE because there are specialized functions to add these headers
   using the IPv6 socket API. These do not offer as much control because they
   are controlled by the OS, and may be reordered, for example. */
static int send_ipv6_ip(const struct sockaddr_in6 *dst,
  const unsigned char *packet, size_t packetlen) {
  struct msghdr msg;
  struct iovec iov;

  const unsigned char *end;
  struct ip6_hdr *hdr;
  unsigned char nxt;
#ifdef IPV6_TCLASS
  int tclass;
#endif
  int hoplimit;

  int sd;
  int n;

  sd = -1;
  n = -1;

  /* Set up sendmsg data structure. iov is filled in below. */
  msg.msg_name = (void *) dst;
  msg.msg_namelen = sizeof(*dst);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  if (packetlen < sizeof(*hdr))
    return -1;
  hdr = (struct ip6_hdr *) packet;

  /* This can also be set with setsockopt(IPPROTO_IPV6, IPV6_TCLASS). */
#ifdef IPV6_TCLASS
  tclass = ntohl(hdr->ip6_flow & IP6_FLOWINFO_MASK) >> 20;
  if (add_ancillary(&msg, IPPROTO_IPV6,
    IPV6_TCLASS, &tclass, sizeof(tclass)) == -1) {
    goto bail;
  }
#endif
  /* This can also be set with setsockopt(IPPROTO_IPV6, IPV6_UNICAST_HOPS). */
  hoplimit = hdr->ip6_hlim;
  if (add_ancillary(&msg, IPPROTO_IPV6,
    IPV6_HOPLIMIT, &hoplimit, sizeof(hoplimit)) == -1) {
    goto bail;
  }
  /* The Next Header field is set when the socket is created. The payload
     length is set in the call to sendmsg. There's no way to set the flow
     label. */

  /* We must loop until we find a nh value acceptable to the operating system
     (one that can be passed as the third parameter to socket). In my tests on
     OS X, you get EPROTOTYPE "Protocol wrong type for socket" for
       43  routing
       44  fragment
       50  ESP
       51  AH
       60  DSTOPT
       108 IPcomp
     Some of these we are able to handle with ancillary data. When that's
     possible, we skip over the header, add the ancillary data, and try again
     with the next header. */
  end = packet + packetlen;
  packet += sizeof(*hdr);
  nxt = hdr->ip6_nxt;
  for (;;) {
    errno = 0;
    sd = socket(AF_INET6, SOCK_RAW, nxt);
    if (!(sd == -1 && errno == EPROTOTYPE))
      break;
    packet = add_exthdr_ancillary(&msg, packet, end - packet, &nxt);
    if (packet == NULL) {
      netutil_error("Can't add extension header %u as ancillary data", nxt);
      goto bail;
    }
  }
  if (sd == -1) {
    perror("socket");
    goto bail;
  }

  assert(packet <= end);
  iov.iov_base = (unsigned char *) packet;
  iov.iov_len = end - packet;

  n = sendmsg(sd, &msg, 0);
  if (n == -1)
    perror("sendmsg");

bail:
  free(msg.msg_control);
  if (sd != -1)
    close(sd);

  return n;
}

#endif

/* For now, the sd argument is ignored. */
int send_ipv6_packet_eth_or_sd(int sd, const struct eth_nfo *eth,
  const struct sockaddr_in6 *dst, const u8 *packet, unsigned int packetlen) {
  if (eth != NULL) {
    return send_ipv6_eth(eth, packet, packetlen);
  } else {
#if HAVE_IPV6_IPPROTO_RAW
    return send_ipv6_ipproto_raw(dst, packet, packetlen);
#elif !WIN32
    return send_ipv6_ip(dst, packet, packetlen);
#endif
  }

  return -1;
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
  static struct NameNotFoundCache {
    char dnetd[64];
  } *NNFC = NULL;
  static int NNFCsz = 0;
  static int NNFCcapacity = 0;
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
  if (!NNFC) {
    NNFCcapacity = 5;
    NNFC =
        (struct NameNotFoundCache *) safe_zalloc(NNFCcapacity *
                                                    sizeof(*NNFC));
    NNFCsz = 0;
  }
  // First check if the name is already in the cache
  for (i = 0; i < NCCsz; i++) {
    if (strcmp(NCC[i].dnetd, dnetdev) == 0) {
      Strncpy(pcapdev, NCC[i].pcapd, pcapdevlen);
      return 1;
    }
  }
  // Check if the name is already in the name not found cache
  for (i = 0; i < NNFCsz; i++) {
    if (strcmp(NNFC[i].dnetd, dnetdev) == 0) {
      return 0;
    }
  }
  // OK, so it isn't in the cache.  Let's ask dnet for it.
  /* Converts a dnet interface name (ifname) to its pcap equivalent, which is stored in
  pcapdev (up to a length of pcapdevlen).  Returns 1 and fills in pcapdev if successful. */
  if (eth_get_pcap_devname(dnetdev, tmpdev, sizeof(tmpdev)) != 0) {
      // We've got it.  Let's add it to the not found cache
      if (NNFCsz >= NNFCcapacity) {
        NNFCcapacity <<= 2;
        NNFC =
            (struct NameNotFoundCache *) safe_realloc(NNFC,
                                                         NNFCcapacity *
                                                         sizeof(*NNFC));
      }
      Strncpy(NNFC[NNFCsz].dnetd, dnetdev, sizeof(NNFC[0].dnetd));
      NNFCsz++;
      return 0;
  }

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


/* This function is  used to obtain a packet capture handle to look at
 * packets on the network. It is actually a wrapper for libpcap's
 * pcap_open_live() that takes care of compatibility issues and error
 * checking. The function attempts to open the device up to three times.
 * If the call does not succeed the third time, NULL is returned. */
pcap_t *my_pcap_open_live(const char *device, int snaplen, int promisc, int to_ms){
  char err0r[PCAP_ERRBUF_SIZE];
  pcap_t *pt;
  char pcapdev[128];
  int failed = 0;

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

#ifdef __amigaos__
  // Amiga doesn't have pcap_create
  // TODO: Does Nmap still work on Amiga?
  pt = pcap_open_live(pcapdev, snaplen, promisc, to_ms, err0r);
  if (!pt) {
    netutil_error("pcap_open_live(%s, %d, %d, %d) FAILED. Reported error: %s.", pcapdev, snaplen, promisc, to_ms, err0r);
    return NULL;
  }
#else
  pt = pcap_create(pcapdev, err0r);
  if (!pt) {
    netutil_error("pcap_create(%s) FAILED: %s.", pcapdev, err0r);
    return NULL;
  }

#define MY_PCAP_SET(func, p_t, val) do {\
  failed = func(p_t, val);\
  if (failed) {\
    netutil_error(#func "(%d) FAILED: %d.", val, failed);\
    pcap_close(p_t);\
    return NULL;\
  }\
} while(0);

  MY_PCAP_SET(pcap_set_snaplen, pt, snaplen);
  MY_PCAP_SET(pcap_set_promisc, pt, promisc);
  MY_PCAP_SET(pcap_set_timeout, pt, to_ms);
#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
  MY_PCAP_SET(pcap_set_immediate_mode, pt, 1);
#endif

  failed = pcap_activate(pt);
  if (failed < 0) {
    // PCAP error
    netutil_error("pcap_activate(%s) FAILED: %s.", pcapdev, pcap_geterr(pt));
    pcap_close(pt);
    return NULL;
  }
  else if (failed > 0) {
    // PCAP warning, report but assume it'll still work
    netutil_error("pcap_activate(%s) WARNING: %s.", pcapdev, pcap_geterr(pt));
  }
#endif /* not __amigaos__ */

#ifdef WIN32
  /* We want any responses back ASAP */
  /* This is unnecessary with Npcap since libpcap calls PacketSetMinToCopy(0)
   * based on immediate mode. Have not determined if it is needed for WinPcap
   * or not, but it's not hurting anything. */
  pcap_setmintocopy(pt, 0);
  /* Npcap sets kernel buffer size to 1MB, but user buffer size to 256KB.
   * Memory is pretty cheap these days, so lets match the kernel buffer size
   * for better performance. */
  pcap_setuserbuffer(pt, 1000000);
#endif

  return pt;
}


/* Set a pcap filter */
void set_pcap_filter(const char *device, pcap_t *pd, const char *bpf, ...) {
  va_list ap;
  int size;
  char buf[3072];
  struct bpf_program fcode;

  va_start(ap, bpf);
  size = Vsnprintf(buf, sizeof(buf), bpf, ap);
  va_end(ap);
  if (size >= (int) sizeof(buf))
    netutil_fatal("%s called with too-large filter arg\n", __func__);

  if (pcap_compile(pd, &fcode, buf, 1, PCAP_NETMASK_UNKNOWN) < 0)
    netutil_fatal("Error compiling our pcap filter: %s", pcap_geterr(pd));
  if (pcap_setfilter(pd, &fcode) < 0)
    netutil_fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));
  pcap_freecode(&fcode);
}


/* Return the data offset for the given datalink. This function understands the
   datalink types DLT_EN10MB and DLT_LINUX_SLL. Returns -1 on error. */
int datalink_offset(int datalink)
{
  int offset = -1;
  /* NOTE: IF A NEW OFFSET EVER EXCEEDS THE CURRENT MAX (24), ADJUST
     MAX_LINK_HEADERSZ in libnetutil/netutil.h */
  switch (datalink) {
  case DLT_EN10MB:
    offset = ETH_HDR_LEN;
    break;
  case DLT_IEEE802:
    offset = 22;
    break;
#ifdef __amigaos__
  case DLT_MIAMI:
    offset = 16;
    break;
#endif
#ifdef DLT_LOOP
  case DLT_LOOP:
#endif
  case DLT_NULL:
    offset = 4;
    break;
  case DLT_SLIP:
#ifdef DLT_SLIP_BSDOS
  case DLT_SLIP_BSDOS:
#endif
#if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
    offset = 16;
#else
    offset = 24; /* Anyone use this??? */
#endif
    break;
  case DLT_PPP:
#ifdef DLT_PPP_BSDOS
  case DLT_PPP_BSDOS:
#endif
#ifdef DLT_PPP_SERIAL
  case DLT_PPP_SERIAL:
#endif
#ifdef DLT_PPP_ETHER
  case DLT_PPP_ETHER:
#endif
#if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
    offset = 4;
#else
#ifdef SOLARIS
    offset = 8;
#else
    offset = 24; /* Anyone use this? */
#endif /* ifdef solaris */
#endif /* if freebsd || openbsd || netbsd || bsdi */
    break;
  case DLT_RAW:
    offset = 0;
    break;
  case DLT_FDDI:
    offset = 21;
    break;
#ifdef DLT_ENC
  case DLT_ENC:
    offset = 12;
    break;
#endif /* DLT_ENC */
#ifdef DLT_LINUX_SLL
  case DLT_LINUX_SLL:
    offset = 16;
    break;
#endif
#ifdef DLT_IPNET
  case DLT_IPNET:
    offset = 24;
    break;
#endif
  default:
    offset = -1;
    break;
  }
  return offset;
}

/* Common subroutine for reading ARP and NS responses. Input parameters are pd,
   to_usec, and accept_callback. If a received frame passes accept_callback,
   then the output parameters p, head, rcvdtime, datalink, and offset are filled
   in, and the function returns 1. If no frame passes before the timeout, then
   the function returns 0 and the output parameters are undefined. */
int read_reply_pcap(pcap_t *pd, long to_usec,
  bool (*accept_callback)(const unsigned char *, const struct pcap_pkthdr *, int, size_t),
  const unsigned char **p, struct pcap_pkthdr **head, struct timeval *rcvdtime,
  int *datalink, size_t *offset)
{
  static int warning = 0;
  int timedout = 0;
  int badcounter = 0;
  struct timeval tv_start, tv_end;
  int ioffset;

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
  if ((*datalink = pcap_datalink(pd)) < 0)
    netutil_fatal("Cannot obtain datalink information: %s", pcap_geterr(pd));
  ioffset = datalink_offset(*datalink);
  if (ioffset < 0)
    netutil_fatal("datalink_offset failed for type %d (DLT_EN10MB = %d, DLT_LINUX_SLL = %d)", *datalink, DLT_EN10MB, DLT_LINUX_SLL);
  *offset = (unsigned int) ioffset;

  if (to_usec > 0) {
    gettimeofday(&tv_start, NULL);
  }

  do {

    *p = NULL;
    int pcap_status = 0;
    /* It may be that protecting this with !pcap_selectable_fd_one_to_one is not
       necessary, that it is always safe to do a nonblocking read in this way on
       all platforms. But I have only tested it on Solaris. */
    if (!pcap_selectable_fd_one_to_one()) {
      int rc, nonblock;

      nonblock = pcap_getnonblock(pd, NULL);
      assert(nonblock == 0);
      rc = pcap_setnonblock(pd, 1, NULL);
      assert(rc == 0);
      pcap_status = pcap_next_ex(pd, head, p);
      rc = pcap_setnonblock(pd, nonblock, NULL);
      assert(rc == 0);
    }

    if (pcap_status == PCAP_ERROR) {
      // TODO: Gracefully end the scan.
      netutil_fatal("Error from pcap_next_ex: %s\n", pcap_geterr(pd));
    }

    if (pcap_status == 0 || *p == NULL) {
      /* Nonblocking pcap_next_ex didn't get anything. */
      if (pcap_select(pd, to_usec) == 0)
        timedout = 1;
      else
        pcap_status = pcap_next_ex(pd, head, p);
    }

    if (pcap_status == PCAP_ERROR) {
      // TODO: Gracefully end the scan.
      netutil_fatal("Error from pcap_next_ex: %s\n", pcap_geterr(pd));
    }

    if (pcap_status == 1 && *p != NULL && accept_callback(*p, *head, *datalink, *offset)) {
      break;
    } else if (pcap_status == 0 || *p == NULL) {
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
    // TODO: come up with a better way to synchronize pcap with gettimeofday.
    // Npcap and WinPcap both suffer from clock drift relative to gettimeofday().
    // We hope to fix this with better time sources for Npcap ( http://issues.nmap.org/1407 )
    // and for Nmap ( http://issues.nmap.org/180 )
    // For now, we use gettimeofday() for Windows in this case.
    // Sometimes the time from the pcap header is a
    // COUPLE SECONDS before the gettimeofday() results :(.
#if defined(WIN32) || defined(__amigaos__)
    gettimeofday(&tv_end, NULL);
    *rcvdtime = tv_end;
#else
    rcvdtime->tv_sec = (*head)->ts.tv_sec;
    rcvdtime->tv_usec = (*head)->ts.tv_usec;
    assert((*head)->ts.tv_sec);
#endif
  }

  return 1;
}

static bool accept_arp(const unsigned char *p, const struct pcap_pkthdr *head,
  int datalink, size_t offset)
{
  if (head->caplen < offset + 28)
    return false;

  /* hw type eth (0x0001), prot ip (0x0800),
     hw size (0x06), prot size (0x04) */
  if (memcmp(p + offset, "\x00\x01\x08\x00\x06\x04\x00\x02", 8) != 0)
    return false;

  if (datalink == DLT_EN10MB) {
    return ntohs(*((u16 *) (p + 12))) == ETH_TYPE_ARP;
  } else if (datalink == DLT_LINUX_SLL) {
    return ntohs(*((u16 *) (p + 2))) == ARPHRD_ETHER && /* sll_hatype */
      ntohs(*((u16 *) (p + 4))) == 6 && /* sll_halen */
      ntohs(*((u16 *) (p + 14))) == ETH_TYPE_ARP; /* sll_protocol */
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
                        void (*trace_callback)(int, const u8 *, u32, struct timeval *)) {
  const unsigned char *p;
  struct pcap_pkthdr *head;
  int datalink;
  size_t offset;
  int rc;

  rc = read_reply_pcap(pd, to_usec, accept_arp, &p, &head, rcvdtime, &datalink, &offset);
  if (rc == 0)
    return 0;

  memcpy(sendermac, p + offset + 8, 6);
  /* I think alignment should allow this ... */
  memcpy(&senderIP->s_addr, p + offset + 14, 4);

  if (trace_callback != NULL) {
    /* TODO: First parameter "2" is a hardcoded value for Nmap's PacketTrace::RECV. */
    trace_callback(2, (u8 *) p + offset, ARP_HDR_LEN + ARP_ETHIP_LEN, rcvdtime);
  }

  return 1;
}

static bool accept_ns(const unsigned char *p, const struct pcap_pkthdr *head,
  int datalink, size_t offset)
{
  struct icmpv6_hdr *icmp6_header;

  if (head->caplen < offset + IP6_HDR_LEN + ICMPV6_HDR_LEN)
    return false;

  icmp6_header = (struct icmpv6_hdr *)(p + offset + IP6_HDR_LEN);
  return icmp6_header->icmpv6_type == ICMPV6_NEIGHBOR_ADVERTISEMENT &&
    icmp6_header->icmpv6_code == 0;
}

/* Attempts to read one IPv6/Ethernet Neighbor Solicitation reply packet from the pcap
   descriptor pd.  If it receives one, fills in sendermac (must pass
   in 6 bytes), senderIP, and rcvdtime (can be NULL if you don't care)
   and returns 1.  If it times out and reads no Neighbor Advertisement, returns
   0.  to_usec is the timeout period in microseconds.  Use 0 to avoid
   blocking to the extent possible.  Returns -1 or exits if there is
   an error.  The last parameter is a pointer to a callback function
   that can be used for packet tracing. This is intended to be used
   by Nmap only. Any other calling this should pass NULL instead. */
int read_ns_reply_pcap(pcap_t *pd, u8 *sendermac,
                        struct sockaddr_in6 *senderIP, long to_usec,
                        struct timeval *rcvdtime, bool *has_mac,
                        void (*trace_callback)(int, const u8 *, u32, struct timeval *)) {
  const unsigned char *p;
  struct pcap_pkthdr *head;
  int datalink;
  size_t offset;
  int rc;
  struct icmpv6_msg_nd *na;

  rc = read_reply_pcap(pd, to_usec, accept_ns, &p, &head, rcvdtime, &datalink, &offset);
  if (rc == 0)
    return 0;

  na = (struct icmpv6_msg_nd *)(p + offset + IP6_HDR_LEN + ICMPV6_HDR_LEN);
  if (head->caplen >= ((unsigned char *)na - p) + sizeof(struct icmpv6_msg_nd) &&
    na->icmpv6_option_type == 2 &&
    na->icmpv6_option_length == 1) {
    *has_mac = true;
    memcpy(sendermac, &na->icmpv6_mac, 6);
  }
  else {
    *has_mac = false;
  }
  senderIP->sin6_family = AF_INET6;
  memcpy(&senderIP->sin6_addr.s6_addr, &na->icmpv6_target, 16);

  if (trace_callback != NULL) {
    /* TODO: First parameter "2" is a hardcoded value for Nmap's PacketTrace::RECV. */
    trace_callback(2, (u8 *) p + offset, IP6_HDR_LEN + ICMPV6_HDR_LEN + 4 + 16 + 8, rcvdtime);
  }

  return 1;
}


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
                   void (*traceND_callback)(int, const u8 *, u32 , struct timeval *)
                    ) {
  /* timeouts in microseconds ... the first ones are retransmit times, while
     the final one is when we give up */
  int timeouts[] = { 100000, 400000, 800000 };
  int max_sends = 3;
  int num_sends = 0; // How many we have sent so far
  eth_t *ethsd;
  u8 frame[ETH_HDR_LEN + IP6_HDR_LEN + ICMPV6_HDR_LEN + 4 + 16 + 8];
  struct timeval start, now, rcvdtime;
  int timeleft;
  int listenrounds;
  int rc;
  bool has_mac;
  pcap_t *pd;
  struct sockaddr_storage rcvdIP;
  rcvdIP.ss_family = AF_INET6;
  bool foundit = false;
  char filterstr[256];
  struct sockaddr_in6 *target_sin6, *src_sin6;
  struct sockaddr_in6 ns_dst_ip6;

  if (targetip->ss_family != AF_INET6 || srcip->ss_family != AF_INET6)
    netutil_fatal("%s can only handle IPv6 addresses", __func__);

  target_sin6 = (struct sockaddr_in6 *) targetip;
  src_sin6 = (struct sockaddr_in6 *) srcip;

  unsigned char ns_dst_mac[6] = {0x33, 0x33, 0xff};
  ns_dst_mac[3] = target_sin6->sin6_addr.s6_addr[13];
  ns_dst_mac[4] = target_sin6->sin6_addr.s6_addr[14];
  ns_dst_mac[5] = target_sin6->sin6_addr.s6_addr[15];

  ns_dst_ip6 = *target_sin6;
  unsigned char multicast_prefix[13] = {0};
  multicast_prefix[0] = 0xff;
  multicast_prefix[1] = 0x02;
  multicast_prefix[11] = 0x1;
  multicast_prefix[12] = 0xff;
  memcpy(ns_dst_ip6.sin6_addr.s6_addr, multicast_prefix, sizeof(multicast_prefix));

  /* Start listening */
  if((pd=my_pcap_open_live(dev, 100, 1, 25))==NULL)
    netutil_fatal("my_pcap_open_live(%s, 50, 1, 25) failed three times.", dev);
  /* Libpcap: IPv6 upper-layer protocol is not supported by proto[x] */
  /* Grab the ICMPv6 type using ip6[X:Y] syntax. This works only if there are no
     extension headers (top-level nh is IPPROTO_ICMPV6). */
  Snprintf(filterstr, 256, "ether dst %02X%02X%02X%02X%02X%02X and icmp6 and ip6[6:1] = %u and ip6[40:1] = %u",
           srcmac[0], srcmac[1], srcmac[2], srcmac[3], srcmac[4], srcmac[5],
	   IPPROTO_ICMPV6, ICMPV6_NEIGHBOR_ADVERTISEMENT);
  set_pcap_filter(dev, pd, filterstr);

  /* Prepare probe and sending stuff */
  ethsd = eth_open_cached(dev);
  if (!ethsd)
    netutil_fatal("%s: failed to open device %s", __func__, dev);
  eth_pack_hdr(frame, *ns_dst_mac, *srcmac, ETH_TYPE_IPV6);
  ip6_pack_hdr(frame + ETH_HDR_LEN, 0, 0, 32, 0x3a, 255, *src_sin6->sin6_addr.s6_addr, *ns_dst_ip6.sin6_addr.s6_addr);
  icmpv6_pack_hdr_ns_mac(frame + ETH_HDR_LEN + IP6_HDR_LEN, target_sin6->sin6_addr.s6_addr, *srcmac);
  ip6_checksum(frame + ETH_HDR_LEN, IP6_HDR_LEN + ICMPV6_HDR_LEN + 4 + 16 + 8);

  gettimeofday(&start, NULL);
  gettimeofday(&now, NULL);

  while (!foundit && num_sends < max_sends) {
    /* Send the sucker */
    rc = eth_send(ethsd, frame, sizeof(frame));
    if (rc != sizeof(frame)) {
     netutil_error("WARNING: %s: eth_send of Neighbor Solicitation packet returned %u rather than expected %d bytes", __func__, rc, (int) sizeof(frame));
    }
    if(traceND_callback!=NULL){
        /* TODO: First parameter "1" is a hardcoded value for Nmap's PacketTrace::SENT*/
        traceND_callback(1, (u8 *) frame + ETH_HDR_LEN, IP6_HDR_LEN + ICMPV6_HDR_LEN + 4 + 16 + 8, &now);
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
      rc = read_ns_reply_pcap(pd, targetmac, (struct sockaddr_in6 *) &rcvdIP, timeleft,
                               &rcvdtime, &has_mac, traceND_callback);
      if (rc == -1)
        netutil_fatal("%s: Received -1 response from read_ns_reply_pcap", __func__);
      if (rc == 1) {
        /* Yay, I got one! But is it the right one? */
        if (sockaddr_storage_cmp(&rcvdIP,targetip) != 0)
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
 */
const char *grab_next_host_spec(FILE *inputfd, int argc, const char **argv) {
  static char host_spec[1024];
  size_t n;

  if (optind < argc) {
    return argv[optind++];
  } else if (inputfd) {
    n = read_host_from_file(inputfd, host_spec, sizeof(host_spec));
    if (n == 0)
      return NULL;
    else if (n >= sizeof(host_spec))
      netutil_fatal("One of the host specifications from your input file is too long (>= %u chars)", (unsigned int) sizeof(host_spec));
    return host_spec;
  }
  return NULL;
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
        if(r.rlim_cur != RLIM_INFINITY && r.rlim_cur < (rlim_t)desired_max){
            if(desired_max<0){
                r.rlim_cur=r.rlim_max; /* Set maximum */
            }else{
                r.rlim_cur = MIN( (int)r.rlim_max, desired_max );
            }
            if (setrlimit(flag, &r))
               ; // netutil_debug("setrlimit(%d, %p) failed", flag, r);
            if (!getrlimit(flag, &r)) {
                maxfds = r.rlim_cur;
                // NOTE: This may be RLIM_INFINITY, which is -1 (~0UL) on Linux.
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
