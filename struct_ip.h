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
#ifndef NETINET_IP_H  /* This guarding is needed for at least some versions of OpenBSD */
#include <netinet/ip.h>
#define NETINET_IP_H
#endif

#ifndef WIN32
#include <netinet/ip_icmp.h>
#endif
