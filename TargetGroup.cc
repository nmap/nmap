
/***************************************************************************
 * TargetGroup.cc -- The "TargetGroup" class holds a group of IP           *
 * addresses, such as those from a '/16' or '10.*.*.*' specification.  It  *
 * also has a trivial HostGroupState class which handles a bunch of        *
 * expressions that go into TargetGroup classes.                           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2008 Insecure.Com LLC. Nmap is    *
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
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://nmap.org to download Nmap.                                       *
 *                                                                         *
 * We don't consider these to be added restrictions on top of the GPL, but *
 * just a clarification of how we interpret "derived works" as it applies  *
 * to our GPL-licensed Nmap product.  This is similar to the way Linus     *
 * Torvalds has announced his interpretation of how "derived works"        *
 * applies to Linux kernel modules.  Our interpretation refers only to     *
 * Nmap - we don't speak for any other GPL products.                       *
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
 * listed in the included COPYING.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
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
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one of the         *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "TargetGroup.h"
#include "NmapOps.h"
#include "nmap_error.h"

extern NmapOps o;

TargetGroup::TargetGroup() {
  Initialize();
}

// Bring back (or start with) original state
void TargetGroup::Initialize() {
  targets_type = TYPE_NONE;
  memset(addresses, 0, sizeof(addresses));
  memset(current, 0, sizeof(current));
  memset(last, 0, sizeof(last));
  ipsleft = 0;
}

/* take the object back to the beginning without  (mdmcl)
 * reinitalizing the data structures */  
int  TargetGroup::rewind() {

  /* For netmasks we must set the current address to the
   * starting address and calculate the ips by distance */
  if (targets_type == IPV4_NETMASK) {
      currentaddr = startaddr;
      if (startaddr.s_addr <= endaddr.s_addr) { 
	ipsleft = ((unsigned long long) (endaddr.s_addr - startaddr.s_addr)) + 1;
	return 0; 
      }
      else
        assert(0);
  }
  /* For ranges, we easily set current to zero and calculate
   * the ips by the number of values in the columns */
  else if (targets_type == IPV4_RANGES) {
    memset((char *)current, 0, sizeof(current));
    ipsleft = (unsigned long long) (last[0] + 1) *
              (unsigned long long) (last[1] + 1) *
              (unsigned long long) (last[2] + 1) *
              (unsigned long long) (last[3] + 1);
    return 0;
  }
#if HAVE_IPV6
  /* For IPV6 there is only one address, this function doesn't
   * make much sence for IPv6 does it? */
  else if (targets_type == IPV6_ADDRESS) {
    ipsleft = 1;
    return 0;
  }
#endif 

  /* If we got this far there must be an error, wrong type */
  return -1;
}

 /* Initializes (or reinitializes) the object with a new expression, such
    as 192.168.0.0/16 , 10.1.0-5.1-254 , or fe80::202:e3ff:fe14:1102 .  
    Returns 0 for success */  
int TargetGroup::parse_expr(const char * const target_expr, int af) {

  int i=0,j=0,k=0;
  int start, end;
  char *r,*s, *target_net;
  char *addy[5];
  char *hostexp = strdup(target_expr);
  struct hostent *target;
  namedhost = 0;

  if (targets_type != TYPE_NONE)
    Initialize();

  ipsleft = 0;

  if (af == AF_INET) {
  
    if (strchr(hostexp, ':'))
      fatal("Invalid host expression: %s -- colons only allowed in IPv6 addresses, and then you need the -6 switch", hostexp);

    /*struct in_addr current_in;*/
    addy[0] = addy[1] = addy[2] = addy[3] = addy[4] = NULL;
    addy[0] = r = hostexp;
    /* First we break the expression up into the four parts of the IP address
       + the optional '/mask' */
    target_net = hostexp;
    s = strchr(hostexp, '/'); /* Find the slash if there is one */
    if (s) {
      *s = '\0';  /* Make sure target_net is terminated before the /## */
      s++; /* Point s at the netmask */
    }
    netmask  = ( s ) ? atoi(s) : 32;
    if ((int) netmask < 0 || netmask > 32) {
      error("Illegal netmask value (%d), must be /0 - /32 .  Assuming /32 (one host)", netmask);
      netmask = 32;
    }
    for(i=0; *(hostexp + i); i++) 
      if (isupper((int) *(hostexp +i)) || islower((int) *(hostexp +i))) {
	namedhost = 1;
	break;
      }
    if (netmask != 32 || namedhost) {
      targets_type = IPV4_NETMASK;
      if (!inet_pton(AF_INET, target_net, &(startaddr))) {
	if ((target = gethostbyname(target_net))) {
          int count=0;

	  memcpy(&(startaddr), target->h_addr_list[0], sizeof(struct in_addr));

          while (target->h_addr_list[count]) count++;

          if (count > 1)
             error("Warning: Hostname %s resolves to %d IPs. Using %s.", target_net, count, inet_ntoa(*((struct in_addr *)target->h_addr_list[0])));
	} else {
	  error("Failed to resolve given hostname/IP: %s.  Note that you can't use '/mask' AND '1-4,7,100-' style IP ranges", target_net);
	  free(hostexp);
	  return 1;
	}
      } 
      if (netmask) {
        unsigned long longtmp = ntohl(startaddr.s_addr);
        startaddr.s_addr = longtmp & (unsigned long) (0 - (1<<(32 - netmask)));
        endaddr.s_addr = longtmp | (unsigned long)  ((1<<(32 - netmask)) - 1);
      } else {
        /* The above calculations don't work for a /0 netmask, though at first
         * glance it appears that they would
         */
        startaddr.s_addr = 0;
        endaddr.s_addr = 0xffffffff;
      }
      currentaddr = startaddr;
      if (startaddr.s_addr <= endaddr.s_addr) { 
	ipsleft = ((unsigned long long) (endaddr.s_addr - startaddr.s_addr)) + 1;
	free(hostexp); 
	return 0; 
      }
      fprintf(stderr, "Host specification invalid");
      free(hostexp);
      return 1;
    }
    else {
      targets_type = IPV4_RANGES;
      i=0;

      while(*++r) {
	if (*r == '.' && ++i < 4) {
	  *r = '\0';
	  addy[i] = r + 1;
	}
	else if (*r != '*' && *r != ',' && *r != '-' && !isdigit((int)*r)) 
	  fatal("Invalid character in  host specification.  Note in particular that square brackets [] are no longer allowed.  They were redundant and can simply be removed.");
      }
      if (i != 3) fatal("Invalid target host specification: %s", target_expr);
      
      for(i=0; i < 4; i++) {
	j=0;
	do {
	  s = strchr(addy[i],',');
	  if (s) *s = '\0';
	  if (*addy[i] == '*') { start = 0; end = 255; } 
	  else if (*addy[i] == '-') {
	    start = 0;
	    if (*(addy[i] + 1) == '\0') end = 255;
	    else end = atoi(addy[i]+ 1);
	  }
	  else {
	    start = end = atoi(addy[i]);
	    if ((r = strchr(addy[i],'-')) && *(r+1) ) end = atoi(r + 1);
	    else if (r && !*(r+1)) end = 255;
	  }
	  /*	  if (o.debugging > 2)
		  log_write(LOG_STDOUT, "The first host is %d, and the last one is %d\n", start, end); */
	  if (start < 0 || start > end || start > 255 || end > 255)
	    fatal("Your host specifications are illegal!");
	  if (j + (end - start) > 255) 
	    fatal("Your host specifications are illegal!");
	  for(k=start; k <= end; k++)
	    addresses[i][j++] = k;
	  last[i] = j-1;
	  if (s) addy[i] = s + 1;
	} while (s);
      }
    }
  memset((char *)current, 0, sizeof(current));
  ipsleft = (unsigned long long) (last[0] + 1) *
            (unsigned long long) (last[1] + 1) *
            (unsigned long long) (last[2] + 1) *
            (unsigned long long) (last[3] + 1);
  }
  else {
#if HAVE_IPV6
    int rc = 0;
    assert(af == AF_INET6);
    if (strchr(hostexp, '/')) {
      fatal("Invalid host expression: %s -- slash not allowed.  IPv6 addresses can currently only be specified individually", hostexp);
    }
    targets_type = IPV6_ADDRESS;
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET6;
    rc = getaddrinfo(hostexp, NULL, &hints, &result);
    if (rc != 0 || result == NULL) {
      error("Failed to resolve given IPv6 hostname/IP: %s.  Note that you can't use '/mask' or '[1-4,7,100-]' style ranges for IPv6.  Error code %d: %s", hostexp, rc, gai_strerror(rc));
      free(hostexp);
      if (result) freeaddrinfo(result);
      return 1;
    }
    assert(result->ai_addrlen == sizeof(struct sockaddr_in6));
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) result->ai_addr;
    memcpy(&ip6, sin6, sizeof(struct sockaddr_in6));
    ipsleft = 1;
    freeaddrinfo(result);
#else // HAVE_IPV6
    fatal("IPv6 not supported on your platform");
#endif // HAVE_IPV6
  }

  free(hostexp);
  return 0;
}

/* For ranges, skip all hosts in an octet,                  (mdmcl)
 * get_next_host should be used for skipping the last octet :-) 
 * returns: number of hosts skipped */
int TargetGroup::skip_range(_octet_nums octet) {
  unsigned long hosts_skipped = 0, /* number of hosts skipped */
      oct = 0;           /* octect number */
      int i = 0;                 /* simple lcv */

  /* This function is only supported for RANGES! */
  if (targets_type != IPV4_RANGES)
    return -1;

  switch (octet) {
    case FIRST_OCTET:
      oct = 0;
      hosts_skipped = (last[1] + 1) * (last[2] + 1) * (last[3] + 1);
      break;
    case SECOND_OCTET:
      oct = 1;
      hosts_skipped = (last[2] + 1) * (last[3] + 1);
      break;
    case THIRD_OCTET:
      oct = 2;
      hosts_skipped = (last[3] + 1);
      break;
    default:  /* Hmm, how'd you do that */
      return -1;
  }

  /* catch if we try to take more than are left */
  assert(ipsleft + 1>= hosts_skipped);

  /* increment the next octect that we can above us */
  for (i = oct; i >= 0; i--) {
    if (current[i] < last[i]) {
      current[i]++;
      break;
    }
    else
      current[i] = 0;
  }

  /* reset all the ones below us to zero */
  for (i = oct+1; i <= 3; i++) {
    current[i] = 0;
  }

  /* we actually don't skip the current, it was accounted for 
   * by get_next_host */
  ipsleft -= hosts_skipped - 1;
 
  return hosts_skipped;
}

 /* Grab the next host from this expression (if any) and updates its internal
    state to reflect that the IP was given out.  Returns 0 and
    fills in ss if successful.  ss must point to a pre-allocated
    sockaddr_storage structure */
int TargetGroup::get_next_host(struct sockaddr_storage *ss, size_t *sslen) {

  int octet;
  struct sockaddr_in *sin = (struct sockaddr_in *) ss;
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ss;
  startover: /* to handle nmap --resume where I have already
		scanned many of the IPs */  
  assert(ss);
  assert(sslen);


  if (ipsleft == 0)
    return -1;
  
  if (targets_type == IPV4_NETMASK) {
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    *sslen = sizeof(struct sockaddr_in);
#if HAVE_SOCKADDR_SA_LEN
    sin->sin_len = *sslen;
#endif
    
    if (currentaddr.s_addr <= endaddr.s_addr) {
      sin->sin_addr.s_addr = htonl(currentaddr.s_addr++);
    } else {
      error("Bogus target structure passed to %s", __func__);
      ipsleft = 0;
      return -1;
    }
  }
  else if (targets_type == IPV4_RANGES) {
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    *sslen = sizeof(struct sockaddr_in);
#if HAVE_SOCKADDR_SA_LEN
    sin->sin_len = *sslen;
#endif
    if (o.debugging > 2) {
      log_write(LOG_STDOUT, "doing %d.%d.%d.%d = %d.%d.%d.%d\n", current[0], current[1], current[2], current[3], addresses[0][current[0]],addresses[1][current[1]],addresses[2][current[2]],addresses[3][current[3]]);
    }
    /* Set the IP to the current value of everything */
    sin->sin_addr.s_addr = htonl(addresses[0][current[0]] << 24 | 
			addresses[1][current[1]] << 16 |
			addresses[2][current[2]] << 8 | 
			addresses[3][current[3]]);
    
    /* Now we nudge up to the next IP */
    for(octet = 3; octet >= 0; octet--) {
      if (current[octet] < last[octet]) {
	/* OK, this is the column I have room to nudge upwards */
	current[octet]++;
	break;
      } else {
	/* This octet is finished so I reset it to the beginning */
	current[octet] = 0;
      }
    }
    if (octet == -1) {
      /* It didn't find anything to bump up, I must have taken the last IP */
      assert(ipsleft == 1);
      /* So I set current to last with the very final octet up one ... */
      /* Note that this may make current[3] == 256 */
      current[0] = last[0]; current[1] = last[1];
      current[2] = last[2]; current[3] = last[3] + 1;
    } else {
      assert(ipsleft > 1); /* There must be at least one more IP left */
    }
  } else {
    assert(targets_type == IPV6_ADDRESS);
    assert(ipsleft == 1);
#if HAVE_IPV6
    *sslen = sizeof(struct sockaddr_in6);
    memset(sin6, 0, *sslen);
    sin6->sin6_family = AF_INET6;
#ifdef SIN_LEN
    sin6->sin6_len = *sslen;
#endif /* SIN_LEN */
    memcpy(sin6->sin6_addr.s6_addr, ip6.sin6_addr.s6_addr, 16);
    sin6->sin6_scope_id = ip6.sin6_scope_id;
#else
    fatal("IPV6 not supported on this platform");
#endif // HAVE_IPV6
  }
  ipsleft--;
  
  /* If we are resuming from a previous scan, we have already finished
     scans up to o.resume_ip.  */
  if (sin->sin_family == AF_INET && o.resume_ip.s_addr) {
    if (o.resume_ip.s_addr == sin->sin_addr.s_addr)
      o.resume_ip.s_addr = 0; /* So that we will KEEP the next one */
    goto startover; /* Try again */
  }

  return 0;
}

/* Returns the last given host, so that it will be given again next
     time get_next_host is called.  Obviously, you should only call
     this if you have fetched at least 1 host since parse_expr() was
     called */
int TargetGroup::return_last_host() {
  int octet;

  ipsleft++;
  if (targets_type == IPV4_NETMASK) {
    assert(currentaddr.s_addr > startaddr.s_addr);
    currentaddr.s_addr--;
  } else if (targets_type == IPV4_RANGES) {
    for(octet = 3; octet >= 0; octet--) {
      if (current[octet] > 0) {
	/* OK, this is the column I have room to nudge downwards */
	current[octet]--;
	break;
      } else {
	/* This octet is already at the beginning, so I set it to the end */
	current[octet] = last[octet];
      }
    }
    assert(octet != -1);
  } else {
    assert(targets_type == IPV6_ADDRESS);
    assert(ipsleft == 1);    
  }
  return 0;
}

/* Lookahead is the number of hosts that can be
   checked (such as ping scanned) in advance.  Randomize causes each
   group of up to lookahead hosts to be internally shuffled around.
   The target_expressions array MUST REMAIN VALID IN MEMORY as long as
   this class instance is used -- the array is NOT copied.
 */
HostGroupState::HostGroupState(int lookahead, int rnd, 
			       char *expr[], int numexpr) {
  assert(lookahead > 0);
  hostbatch = (Target **) safe_zalloc(sizeof(Target *) * lookahead);
  max_batch_sz = lookahead;
  current_batch_sz = 0;
  next_batch_no = 0;
  randomize = rnd;
  target_expressions = expr;
  num_expressions = numexpr;
  next_expression = 0;
}

HostGroupState::~HostGroupState() {
  free(hostbatch);
}
