
/***************************************************************************
 * common_modified.cc --  This file holds all those functions and classes  *
 * that have been reused from Nmap's code but that needed to be modified   *
 * in order to reuse them.                                                 *
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
#include "nping.h"
#include "common.h"
#include "common_modified.h"
#include "output.h"
#include "../libnetutil/netutil.h"
/*****************************************************************************
  * STUFF FROM TargetGroup.cc
  ****************************************************************************

  CHANGES:
       Modified parse_expr.
       Modified get_next_host:

*/


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
 * reinitializing the data structures */
int TargetGroup::rewind() {

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
   * make much sense for IPv6 does it? */
  else if (targets_type == IPV6_ADDRESS) {
    ipsleft = 1;
    return 0;
  }
#endif

  /* If we got this far there must be an error, wrong type */
  return -1;
}



/* For ranges, skip all hosts in an octet,                  (mdmcl)
 * get_next_host should be used for skipping the last octet :-)
 * returns: number of hosts skipped */
int TargetGroup::skip_range(_octet_nums octet) {
   u32 hosts_skipped = 0, /* number of hosts skipped */
      oct = 0;           /* octect number */
      int i = 0;                 /* simple lcv */

  /* This function is only supported for RANGES! */
  if (targets_type != IPV4_RANGES)
    return -1;

  switch (octet) {
    case FIRST_OCTET:
      oct = 0;
      hosts_skipped = (u32)(last[1] + 1) * (last[2] + 1) * (last[3] + 1);
      break;
    case SECOND_OCTET:
      oct = 1;
      hosts_skipped = (u32)(last[2] + 1) * (last[3] + 1);
      break;
    case THIRD_OCTET:
      oct = 2;
      hosts_skipped = (last[3] + 1);
      break;
    default:  /* Hmm, how did you do that? */
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

  /* CHANGE: Commented out. See note at the end of the method */
  //startover: /* to handle nmap --resume where I have already
  //            * scanned many of the IPs */
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
    //if (o.debugging > 2) { /* CHANGE: Do not use NmapOps and do not use log_Write*/
    //  log_write(LOG_STDOUT, "doing %d.%d.%d.%d = %d.%d.%d.%d\n", current[0], current[1], current[2], current[3], addresses[0][current[0]],addresses[1][current[1]],addresses[2][current[2]],addresses[3][current[3]]);
    //}
    //nping_print(DBG_2, "doing %d.%d.%d.%d = %d.%d.%d.%d", current[0], current[1], current[2], current[3], addresses[0][current[0]],addresses[1][current[1]],addresses[2][current[2]],addresses[3][current[3]]);


    /* Set the IP to the current value of everything */
    sin->sin_addr.s_addr = htonl(addresses[0][current[0]] << 24 |
                                 addresses[1][current[1]] << 16 |
                                 addresses[2][current[2]] <<  8 |
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


  /* CHANGE: These lines have been commented out to make this code
   * independent from NmapOps  */
  /* If we are resuming from a previous scan, we have already finished
     scans up to o.resume_ip.  */
 // if (sin->sin_family == AF_INET && o.resume_ip.s_addr) {
 //   if (o.resume_ip.s_addr == sin->sin_addr.s_addr)
 //     o.resume_ip.s_addr = 0; /* So that we will KEEP the next one */
 //   goto startover; /* Try again */
 // }

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





/* TODO: WARNING: This functions has been modified for portability. Check
 * for label "CHANGE:" in the code to see the actual changes.
 *
 * UPDATE: Added support for DNS resolution caching. Using function
 * gethostbynameCached() instead of gethostbyname()
 */
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
      char *tail;
      long netmask_long;

      *s = '\0';  /* Make sure target_net is terminated before the /## */
      s++;        /* Point s at the netmask */
      if (!isdigit(*s)) {
        error("Illegal netmask value, must be /0 - /32 .  Assuming /32 (one host)");
        netmask = 32;
      } else {
        netmask_long = strtol(s, (char**) &tail, 10);
        if (*tail != '\0' || tail == s || netmask_long < 0 || netmask_long > 32) {
          error("Illegal netmask value, must be /0 - /32 .  Assuming /32 (one host)");
          netmask = 32;
        } else
          netmask = (u32) netmask_long;
      }
    } else
      netmask = 32;
    for(i=0; *(hostexp + i); i++)
      if (isupper((int) *(hostexp +i)) || islower((int) *(hostexp +i))) {
        namedhost = 1;
        break;
      }
    if (netmask != 32 || namedhost) {
      targets_type = IPV4_NETMASK;
      if (!inet_pton(AF_INET, target_net, &(startaddr))) {

        /* There is a bug report on the use of gethostbynameCached()
         * <http://seclists.org/nmap-dev/2010/q1/803>
         * I haven't been able to find any problem with that code but
         * still, the fact that DNS queries are cached does not improve
         * performance a lot. It may save one DNS query per execution
         * in those cases where NpingOps::validateOptions() grabs the
         * first target and uses it to determine output network interface.
         * It would also save some queries in the case where a user
         * specified the same host twice in the commandlined, something
         * that does not make much sense anyway. However, since the call
         * to gethostbynameCached() seems to cause denial of service
         * for some people, I think it's ok to disable its use for now
         * and enable it later if there is a good reason for it.
         *
         * Luis MartinGarcia. */
        //if ((target = gethostbynameCached(target_net))) {
        if ((target = gethostbyname(target_net))) {
          int count=0;

          memcpy(&(startaddr), target->h_addr_list[0], sizeof(struct in_addr));

          while (target->h_addr_list[count]) count++;

          if (count > 1)
             nping_print(DBG_2,"Warning: Hostname %s resolves to %d IPs. Using %s.", target_net, count, inet_ntoa(*((struct in_addr *)target->h_addr_list[0])));
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

      while(*r) {
        if (*r == '.' && ++i < 4) {
          *r = '\0';
          addy[i] = r + 1;
        }
        else if (*r != '*' && *r != ',' && *r != '-' && !isdigit((int)*r))
          fatal("Invalid character in host specification.  Note in particular that square brackets [] are no longer allowed.  They were redundant and can simply be removed.");
        r++;
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
       /* if (o.debugging > 2)
        *   log_write(LOG_STDOUT, "The first host is %d, and the last one is %d\n", start, end); */
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

/*****************************************************************************/
/* getpts() and getpts_simple() (see above) are wrappers for this function */
void getpts_aux(const char *origexpr, int nested, u8 *porttbl, int *portwarning) {
  long rangestart = -2343242, rangeend = -9324423;
  const char *current_range;
  char *endptr;
  //char servmask[128];  // A protocol name can be up to 127 chars + nul byte
  //int i;

  /* An example of proper syntax to use in error messages. */
  const char *syntax_example;
  //if (change_range_type)
  //  syntax_example = "-100,200-1024,T:3000-4000,U:60000-";
  //else
    syntax_example = "-100,200-1024,3000-4000,60000-";

  current_range = origexpr;
  do {
    while(isspace((int) *current_range))
      current_range++; /* I don't know why I should allow spaces here, but I will */

    //if (change_range_type) {
      //if (*current_range == 'T' && *++current_range == ':') {
          //current_range++;
          //range_type = SCAN_TCP_PORT;
          //continue;
      //}
      //if (*current_range == 'U' && *++current_range == ':') {
          //current_range++;
          //range_type = SCAN_UDP_PORT;
          //continue;
      //}
      //if (*current_range == 'S' && *++current_range == ':') {
          //current_range++;
          //range_type = SCAN_SCTP_PORT;
          //continue;
      //}
      //if (*current_range == 'P' && *++current_range == ':') {
          //current_range++;
          //range_type = SCAN_PROTOCOLS;
          //continue;
      //}
    //}

    if (*current_range == '[') {
      if (nested)
        fatal("Can't nest [] brackets in port/protocol specification");

      //getpts_aux(++current_range, 1, porttbl, range_type, portwarning);
        getpts_aux(++current_range, 1, porttbl, portwarning); // ADDED

      // Skip past the ']'. This is OK because we can't nest []s
      while(*current_range != ']') current_range++;
      current_range++;

      // Skip over a following ',' so we're ready to keep parsing
      if (*current_range == ',') current_range++;

      continue;
    } else if (*current_range == ']') {
      if (!nested)
        fatal("Unexpected ] character in port/protocol specification");

      return;
    } else if (*current_range == '-') {
      //if (range_type & SCAN_PROTOCOLS)
      //  rangestart = 0;
      //else
        rangestart = 1;
    }
    else if (isdigit((int) *current_range)) {
      rangestart = strtol(current_range, &endptr, 10);
      //if (range_type & SCAN_PROTOCOLS) {
      //  if (rangestart < 0 || rangestart > 255)
	  //fatal("Protocols to be scanned must be between 0 and 255 inclusive");
      //} else {
        if (rangestart < 0 || rangestart > 65535)
	        fatal("Ports to be scanned must be between 0 and 65535 inclusive");
      //}
      current_range = endptr;
      while(isspace((int) *current_range)) current_range++;
    } //else if (islower((int) *current_range) || *current_range == '*' || *current_range == '?') {
      //i = 0;

      //while (*current_range && !isspace((int)*current_range) && *current_range != ',' && *current_range != ']') {
      //  servmask[i++] = *(current_range++);
      //  if (i >= ((int)sizeof(servmask)-1))
      //    fatal("A service mask in the port/protocol specification is either malformed or too long");
     // }

     // if (*current_range && *current_range != ']') current_range++; // We want the '] character to be picked up on the next pass
     // servmask[i] = '\0'; // Finish the string

      //i = addportsfromservmask(servmask, porttbl, range_type);
      //if (range_type & SCAN_PROTOCOLS) i += addprotocolsfromservmask(servmask, porttbl);

      //if (i == 0)
      //  fatal("Found no matches for the service mask '%s' and your specified protocols", servmask);

      //continue;

    /*}*/ else {
      fatal("Error #485: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }
    /* Now I have a rangestart, time to go after rangeend */
    if (!*current_range || *current_range == ',' || *current_range == ']') {
      /* Single port specification */
      rangeend = rangestart;
    } else if (*current_range == '-') {
      current_range++;
      if (!*current_range || *current_range == ',' || *current_range == ']') {
	/* Ended with a -, meaning up until the last possible port */
        //if (range_type & SCAN_PROTOCOLS)
        //  rangeend = 255;
        //else
          rangeend = 65535;
      } else if (isdigit((int) *current_range)) {
	rangeend = strtol(current_range, &endptr, 10);
   //     if (range_type & SCAN_PROTOCOLS) {
//	  if (rangeend < 0 || rangeend > 255)
//	    fatal("Protocols to be scanned must be between 0 and 255 inclusive");
//	} else {
	  if (rangeend < 0 || rangeend > 65535)
	    fatal("Ports to be scanned must be between 0 and 65535 inclusive");
//	}
	current_range = endptr;
      } else {
	fatal("Error #486: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
      }
      if (rangeend < rangestart) {
        //fatal("Your %s range %ld-%ld is backwards. Did you mean %ld-%ld?",
        //  (range_type & SCAN_PROTOCOLS) ? "protocol" : "port",
        //  rangestart, rangeend, rangeend, rangestart);
        fatal("Your port range %ld-%ld is backwards. Did you mean %ld-%ld?",
          rangestart, rangeend, rangeend, rangestart);     // ADDED


      }
    } else {
	fatal("Error #487: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }

    /* Now I have a rangestart and a rangeend, so I can add these ports */
    while(rangestart <= rangeend) {
      if (porttbl[rangestart]) {
        if (!(*portwarning)) {
	        error("WARNING: Duplicate port number(s) specified.  Are you alert enough to be using Nping?  Have some coffee or grab a RedBull(tm).");
            (*portwarning)++;
	    }
      } else {
        //if (nested) {
          //if ((range_type & SCAN_TCP_PORT) &&
              //nmap_getservbyport(rangestart, "tcp")) {
            //porttbl[rangestart] |= SCAN_TCP_PORT;
          //}
          //if ((range_type & SCAN_UDP_PORT) &&
              //nmap_getservbyport(rangestart, "udp")) {
            //porttbl[rangestart] |= SCAN_UDP_PORT;
          //}
          //if ((range_type & SCAN_SCTP_PORT) &&
              //nmap_getservbyport(rangestart, "sctp")) {
            //porttbl[rangestart] |= SCAN_SCTP_PORT;
          //}
          //if ((range_type & SCAN_PROTOCOLS) &&
              //nmap_getprotbynum(rangestart)) {
            //porttbl[rangestart] |= SCAN_PROTOCOLS;
          //}
        //} else {
          //porttbl[rangestart] |= range_type;
        //}

         porttbl[rangestart]=1; // ADDED for NPING
      }
      rangestart++;
    }

    /* Find the next range */
    while(isspace((int) *current_range)) current_range++;

    if (*current_range == ']') {
      if (!nested) fatal("Unexpected ] character in port specification");
      return;
    }

    if (*current_range && *current_range != ',') {
      fatal("Error #488: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }
    if (*current_range == ',')
      current_range++;
  } while(current_range && *current_range);

}
/*****************************************************************************/
















/* For systems without SCTP in netinet/in.h, such as MacOS X */
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif




/* IPv6 compatible version of Nmap's devname2ipaddr()
 * @warning For this to work we need getinterfaces() not to skip IPv6 */
int devname2ipaddr_alt(char *dev, struct sockaddr_storage *addr) {
struct interface_info *mydevs;
struct sockaddr_storage *s=NULL;
struct sockaddr_in *s4=NULL;
struct sockaddr_in6 *s6=NULL;
int numdevs;
int i;
mydevs = getinterfaces(&numdevs, NULL, 0);

if (!mydevs) return -1;

if( !addr || !dev )
    fatal("devname2ipaddr(): NULL values supplied.");

  for(i=0; i < numdevs; i++) {
    s=(struct sockaddr_storage *)&mydevs[i].addr;
    s4=(struct sockaddr_in *)&mydevs[i].addr;
    s6=(struct sockaddr_in6 *)&mydevs[i].addr;
    if (s4->sin_family==AF_INET || s6->sin6_family==AF_INET6){
        if (!strcmp(dev, mydevs[i].devfullname)) {
            memcpy(addr, s, sizeof(struct sockaddr_storage));
            return 0;
        }    
    } else{ /* Unknown family, skipping it... */
      continue;
    }
  }
  return -1;

} /* End of devname2ipaddr() */









