/* The C library on AIX defines the names of various members of struct ip to
   something else in <netinet/ip.h>:

struct ip {
	struct	ip_firstfour ip_ff;
#define	ip_v	ip_ff.ip_fv
#define	ip_hl	ip_ff.ip_fhl
#define	ip_vhl	ip_ff.ip_fvhl
#define	ip_tos	ip_ff.ip_ftos
#define	ip_len	ip_ff.ip_flen

   This breaks code that actually wants to use names like ip_v for its own
   purposes, like struct ip_hdr in libdnet. The AIX definitions will work
   if they are included late in the list of includes, before other code that
   might want to use the above names has already been preprocessed. The
   includes that end up defining struct ip are therefore limited to this
   file, so it can be included in a .cc file after other .h have been
   included. */

/* Linux uses these defines in netinet/ip.h to use the correct struct ip */
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

/* BSDI needs this to insure the correct struct ip */
#undef _IP_VHL

#ifndef NETINET_IN_SYSTM_H  /* This guarding is needed for at least some versions of OpenBSD */
#include <netinet/in_systm.h> /* defines n_long needed for netinet/ip.h */
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
#include <net/if_arp.h>

#ifndef WIN32
#include <netinet/ip_icmp.h>
#endif

#ifndef HAVE_STRUCT_IP
#define HAVE_STRUCT_IP

/* From Linux glibc, which apparently borrowed it from
   BSD code.  Slightly modified for portability --fyodor@nmap.org */
/*
 * Structure of an internet header, naked of options.
 */
struct ip
  {
#if WORDS_BIGENDIAN
    u_int8_t ip_v:4;                    /* version */
    u_int8_t ip_hl:4;                   /* header length */
#else
    u_int8_t ip_hl:4;                   /* header length */
    u_int8_t ip_v:4;                    /* version */ 
#endif
    u_int8_t ip_tos;                    /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    u_int8_t ip_ttl;                    /* time to live */
    u_int8_t ip_p;                      /* protocol */
    u_short ip_sum;                     /* checksum */
    struct in_addr ip_src, ip_dst;      /* source and dest address */
  };

#endif /* HAVE_STRUCT_IP */

#ifndef HAVE_STRUCT_ICMP
#define HAVE_STRUCT_ICMP
/* From Linux /usr/include/netinet/ip_icmp.h GLIBC */

/*
 * Internal of an ICMP Router Advertisement
 */
struct icmp_ra_addr
{
  u_int32_t ira_addr;
  u_int32_t ira_preference;
};

struct icmp
{
  u_int8_t  icmp_type;  /* type of message, see below */
  u_int8_t  icmp_code;  /* type sub code */
  u_int16_t icmp_cksum; /* ones complement checksum of struct */
  union
  {
    struct ih_idseq             /* echo datagram */
    {
      u_int16_t icd_id;
      u_int16_t icd_seq;
    } ih_idseq;
    u_int32_t ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    struct ih_pmtu
    {
      u_int16_t ipm_void;
      u_int16_t ipm_nextmtu;
    } ih_pmtu;

    struct ih_rtradv
    {
      u_int8_t irt_num_addrs;
      u_int8_t irt_wpa;
      u_int16_t irt_lifetime;
    } ih_rtradv;
  } icmp_hun;
  /* Removed icmp_pptr and icmp_gwaddr from union and #defines because they conflict with dnet */
#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void       icmp_hun.ih_void
#define icmp_pmvoid     icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa        icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
  union
  {
    struct
    {
      u_int32_t its_otime;
      u_int32_t its_rtime;
      u_int32_t its_ttime;
    } id_ts;
    struct
    {
      struct ip idi_ip;
      /* options and then 64 bits of data */
    } id_ip;
    struct icmp_ra_addr id_radv;
    u_int32_t   id_mask;
    u_int8_t    id_data[1];
  } icmp_dun;
#define icmp_otime      icmp_dun.id_ts.its_otime
#define icmp_rtime      icmp_dun.id_ts.its_rtime
#define icmp_ttime      icmp_dun.id_ts.its_ttime
#define icmp_ip         icmp_dun.id_ip.idi_ip
#define icmp_radv       icmp_dun.id_radv
#define icmp_mask       icmp_dun.id_mask
#define icmp_data       icmp_dun.id_data
};
#endif /* HAVE_STRUCT_ICMP */
