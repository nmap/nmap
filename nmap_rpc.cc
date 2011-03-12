
/***************************************************************************
 * nmap_rpc.cc -- Functions related to the RPCGrind facility of Nmap.      *
 * This includes reading the nmap-rpc services file and sending rpc        *
 * queries and interpreting responses.  The actual scan engine used for    *
 * rpc grinding is pos_scan (which is not in this file)                    *
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

/* $Id$ */


#include "nmap_rpc.h"
#include "NmapOps.h"
#include "Target.h"
#include "charpool.h"
#include "timing.h"
#include "nmap_error.h"
#include "utils.h"
#include "nbase.h"

extern NmapOps o;
static struct rpc_info ri;
static int udp_rpc_socket = -1;
static int tcp_rpc_socket = -1;
static unsigned long rpc_xid_base = (unsigned long) -1;
					   /* The XID we send in queries is 
					   this random base number + the 
					   RPC prog number we are scanning
					   for */
static size_t tcp_readlen=0; /* used in get_rpc_results but can be reset in 
			    send_rpc_query */

static void rpc_services_init() {
  static int services_initialized = 0;
  if (services_initialized) return;
  services_initialized = 1;

  char filename[512];
  FILE *fp;
  char *tmpptr, *p;
  char line[1024];
  int lineno = 0;

  ri.num_alloc = 256;
  ri.num_used = 0;
  ri.names = (char **) cp_alloc(ri.num_alloc * sizeof(char *));
  ri.numbers = (unsigned long *) cp_alloc(ri.num_alloc * sizeof(unsigned long));

  if (nmap_fetchfile(filename, sizeof(filename), "nmap-rpc") != 1) {
    error("Unable to find nmap-rpc!  Resorting to /etc/rpc");
    strcpy(filename, "/etc/rpc");
  }

  fp = fopen(filename, "r");
  if (!fp) {
    fatal("Unable to open %s for reading rpc information", filename);
  }
  /* Record where this data file was found. */
  o.loaded_data_files["nmap-rpc"] = filename;

  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    p = line;

    if (ri.num_used == ri.num_alloc) {
      tmpptr = (char *) cp_alloc(ri.num_alloc * 3 * sizeof(char *));
      memcpy(tmpptr, ri.names, ri.num_alloc * sizeof(char *));
      ri.names = (char **) tmpptr;
      tmpptr = (char *) cp_alloc(ri.num_alloc * 3 * sizeof(unsigned long));
      memcpy(tmpptr, ri.numbers, ri.num_alloc * sizeof(char *));
      ri.numbers = (unsigned long *) tmpptr;
      ri.num_alloc *= 3;
    }

    while(*p && *p != '#' && !isalnum((int) (unsigned char) *p)) p++;

    if (!*p || *p == '#') continue;

    tmpptr = strpbrk(p, " \t");
    if (!tmpptr) 
      continue;
    *tmpptr = '\0';
    
    ri.names[ri.num_used] = cp_strdup(p);
    p = tmpptr + 1;

    while(*p && !isdigit((int) (unsigned char) *p)) p++;

    if (!*p)
      continue;

    ri.numbers[ri.num_used] = strtoul(p, NULL, 10);
    ri.num_used++;
  }
  fclose(fp);
  return;
}

char *nmap_getrpcnamebynum(unsigned long num) {
  int i;

  rpc_services_init();

  for(i=0; i < ri.num_used; i++) {
    if (ri.numbers[i] == num)
      return ri.names[i];
  }
  return NULL;
}

int get_rpc_procs(unsigned long **programs, unsigned long *num_programs) {
  rpc_services_init();
  
  *programs = ri.numbers;
  *num_programs = ri.num_used;
  if (ri.num_used == 0) fatal("Unable to find any valid rpc procedures in your rpc file!  RPC scanning won't work for you");
  return 0;
}

/* Send an RPC query to the specified host/port on the specified protocol
   looking for the specified RPC program.  We cache our sending sockets
   to avoid recreating and (with TCP) reconnect()'ing them each time */
int send_rpc_query(Target *target_host, unsigned short portno,
		   int ipproto, unsigned long program, int scan_offset, 
		   int trynum) {
  static struct sockaddr_storage last_target;
  struct sockaddr_storage sock;
  size_t socklen;
  static int last_ipproto = -1;
  struct sockaddr_in *sin = NULL, *lastsin = NULL;
#ifdef HAVE_IPV6
  struct sockaddr_in6 *sin6 = NULL, *lastsin6 = NULL;
#endif
  char rpch_buf[256]; 
  struct rpc_hdr *rpch;
  int res, err = 0;

  /* static int numruns = 0;
     if (numruns++ > 2)
     fatal("Done");  */

  rpch = (struct rpc_hdr *) ((char *)rpch_buf + sizeof(unsigned long));
  memset(rpch, 0, sizeof(struct rpc_hdr));


  while(rpc_xid_base == (unsigned long) -1)
    rpc_xid_base = (unsigned long) get_random_uint();
  
  if (o.debugging > 1) {
    log_write(LOG_PLAIN, "Sending RPC probe for program %li to %hu/%s -- scan_offset=%d trynum=%d xid=%lX\n", program, portno, proto2ascii_lowercase(ipproto), scan_offset, trynum, rpc_xid_base + ((portno & 0x3FFF) << 16) + (trynum << 30) +  scan_offset);
  }

  memset(&sock, 0, sizeof(sock));
  target_host->TargetSockAddr(&sock, &socklen);

  if (sock.ss_family == AF_INET) {
    sin = (struct sockaddr_in *) &sock;
    lastsin = (struct sockaddr_in *) &last_target;

    sin->sin_port = htons(portno);
  }
#ifdef HAVE_IPV6
  else {
    sin6 = (struct sockaddr_in6 *) &sock;
    lastsin6 = (struct sockaddr_in6 *) &last_target;

    sin6->sin6_port = htons(portno);
  }
#endif

  /* First we check whether we have to create a new connection -- we 
     need to if we have a new target_host, or a new portno, or the socket
     we want to use is -1 */
  if (ipproto == IPPROTO_TCP) {
    if ((sock.ss_family == AF_INET &&
         memcmp(sin, lastsin, sizeof(struct sockaddr_in)))
#ifdef HAVE_IPV6
     || (sock.ss_family == AF_INET6 &&
         memcmp(sin6, lastsin6, sizeof(struct sockaddr_in6)))
#endif
     || last_ipproto != IPPROTO_TCP) {
      /* New host or port -- kill our old tcp socket */
      if (tcp_rpc_socket != -1) {
        close(tcp_rpc_socket);
        tcp_rpc_socket = -1;
        tcp_readlen = 0;
      }
    }
  }
  
  last_target = sock;
  last_ipproto = ipproto;

  if (ipproto == IPPROTO_TCP && tcp_rpc_socket == -1) {
    if ((tcp_rpc_socket = socket(sock.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
      pfatal("Socket troubles in %s", __func__);
    /* I should unblock the socket here and timeout the connect() */
    res = connect(tcp_rpc_socket, (struct sockaddr *) &sock, socklen);
    if (res == -1) {
      if (o.debugging) {
	gh_perror("Failed to connect to port %d of %s in %s",
		  portno, target_host->targetipstr(), __func__);
      }
      close(tcp_rpc_socket);
      tcp_rpc_socket = -1;
      return -1;
    }
    unblock_socket(tcp_rpc_socket);
  } else if (ipproto == IPPROTO_UDP && udp_rpc_socket == -1) {
    if ((udp_rpc_socket = socket(sock.ss_family, SOCK_DGRAM, 0)) == -1)
      pfatal("UDP socket troubles in %s", __func__);
    unblock_socket(udp_rpc_socket);
  }
  
  /* OK, now that we have our sockets together, we form and send a
     query ... */
  rpch->type_msg = htonl(RPC_MSG_CALL); /* rpc request                 */
  rpch->version_rpc=htonl(2);           /* portmapper v.2 (hmm, and v3&&4?) */
  /*rpch->prog_proc=0;*/                    /* proc_null() rpc function     */
  /*rpch->authcred_flavor=0;*/              /* AUTH_NULL for credentials    */
  /*rpch->authcred_length=0;*/              /* length of credentials is zero*/
  /*rpch->authveri_flavor=0;*/              /* no verifiers field          */
  /*rpch->authveri_length=0;*/              /* zero length verifier field  */
  
  /* Bits are TTPPPPPPPPPPPPPP BBBBBBBBBBBBBBBB */
  /* Where T are trynum bits, P is the lowest 14 bits of the port number,
     and B is the scan[] offset */
  rpch->xid = htonl(rpc_xid_base + ((portno & 0x3FFF) << 16) + 
		    (trynum << 30) +  scan_offset); 
  rpch->prog_id = htonl(program);
  rpch->prog_ver = htonl(31337 + (rpc_xid_base & 0xFFFFF));
  
  if (ipproto == IPPROTO_UDP) {
    /* Simply send this sucker we have created ... */
    do {  
      if (o.debugging > 1)
	  nmap_hexdump((unsigned char *) rpch, sizeof(struct rpc_hdr));
      res = sendto(udp_rpc_socket, (char *)rpch, sizeof(struct rpc_hdr), 0,
		   (struct sockaddr *) &sock, socklen);
      if (res == -1)
	err = socket_errno();
     } while(res == -1 && (err == EINTR || err == ENOBUFS));


    if (res == -1) {
      if (o.debugging) {
	gh_perror("Sendto in %s", __func__);
	close(udp_rpc_socket);
	udp_rpc_socket = -1;
      }
      return -1;
    }
  } else {
    /* TCP socket */
    /* 0x80000000 means only 1 record marking */
    *(unsigned long *)rpch_buf = htonl(sizeof(struct rpc_hdr) | 0x80000000);
    res = Send(tcp_rpc_socket, rpch_buf, sizeof(struct rpc_hdr) + sizeof(unsigned long), 0);
    if (res == -1) {
      if (o.debugging) {
	gh_perror("Write in %s", __func__);
      }
      close(tcp_rpc_socket);
      tcp_rpc_socket = -1;
      return -1;
    }
  }
  return 0;
}

static int rpc_are_we_done(char *msg, int msg_len, Target *target, 
		    struct portinfo *scan, struct scanstats *ss, 
		    struct portinfolist *pil, struct rpcscaninfo *rsi) {

  struct rpc_hdr_rcv *rpc_pack;
  unsigned long scan_offset;
  int trynum;
  struct portinfo *current;

  if (rsi->rpc_current_port->state == PORT_OPENFILTERED) {
    /* Received a packet, so this port is actually open */
     target->ports.setPortState(rsi->rpc_current_port->portno, 
			   rsi->rpc_current_port->proto, PORT_OPEN);
  }

  rpc_pack = (struct rpc_hdr_rcv *) msg;     
  if (msg_len < 24 || msg_len > 32 || (msg_len < 32 && rpc_pack->accept_stat == PROG_MISMATCH)) {
    /* This is not a valid reply -- we kill the port 
       (from an RPC perspective) */ 
    if (o.debugging > 1) {
      log_write(LOG_PLAIN, "Port %hu/%s labelled NON_RPC because of invalid sized message (%d)\n", 
		rsi->rpc_current_port->portno, 
		proto2ascii_uppercase(rsi->rpc_current_port->proto), msg_len);
    }
    rsi->rpc_status = RPC_STATUS_NOT_RPC;
    ss->numqueries_outstanding = 0;
    return 1;
  }

  /* Now it is time to decode the scan offset */
  scan_offset = ntohl(rpc_pack->xid);
  scan_offset -= rpc_xid_base;
  if (((scan_offset >> 16) & 0x3FFF) != (unsigned long) (rsi->rpc_current_port->portno & 0x3FFF)) {
    /* Doh -- this doesn't seem right */
    if (o.debugging > 1) {
      log_write(LOG_PLAIN, "Port %hu/%s labelled NON_RPC because ((scan_offset >> 16) & 0x3FFF) is %li\n", rsi->rpc_current_port->portno, proto2ascii_uppercase(rsi->rpc_current_port->proto), ((scan_offset >> 16) & 0x3FFF));
    }
    rsi->rpc_status = RPC_STATUS_NOT_RPC;
    ss->numqueries_outstanding = 0;
    return 1;
  }
  trynum = scan_offset >> 30;
  scan_offset &= 0xFFFF;
  if (scan_offset >= rsi->rpc_number) {
    error("Invalid scan_offset returned in RPC packet");
    rsi->rpc_status = RPC_STATUS_NOT_RPC;
    ss->numqueries_outstanding = 0;
    return 1;
  }
  if (ntohl(rpc_pack->type_msg) != RPC_MSG_REPLY) {
    error("Strange -- RPC type is %lu should be RPC_MSG_REPLY (1)", (unsigned long) ntohl(rpc_pack->type_msg));
    return 0;
  }
  if (ntohl(rpc_pack->auth_flavor) != 0 /* AUTH_NULL */ ||
      ntohl(rpc_pack->opaque_length != 0)) {
    error("Strange -- auth flavor/opaque_length are %lu/%lu should generally be 0/0", rpc_pack->auth_flavor, rpc_pack->opaque_length);
    rsi->rpc_status = RPC_STATUS_NOT_RPC;
    ss->numqueries_outstanding = 0;
    return 1;
  }

  /* OK, now that we know what this is a response to, we delete the
      appropriate entry from our scanlist */
  current = &scan[scan_offset];
   
  if (current->state != PORT_TESTING && current->state != PORT_CLOSED &&
      current->state != PORT_FILTERED) {
    error("Supposed scan_offset refers to port in state %s (should be testing, closed, or filtered)", statenum2str(current->state));
    rsi->rpc_status = RPC_STATUS_NOT_RPC;
    ss->numqueries_outstanding = 0;
    return 1;
  }
     
  if (trynum > current->trynum) {
    error("Bogus trynum %d when we are only up to %d in %s", trynum, current->trynum, __func__);
    rsi->rpc_status = RPC_STATUS_NOT_RPC;
    ss->numqueries_outstanding = 0;
    return 1;
  }

  if (current->next > -1) scan[current->next].prev = current->prev;
  if (current->prev > -1) scan[current->prev].next = current->next;
  if (current == pil->testinglist)
    pil->testinglist = (current->next >= 0)?  &scan[current->next] : NULL;
  current->next = -1;
  current->prev = -1;
     
     /* Adjust timeouts ... */
  adjust_timeouts(current->sent[trynum], &(target->to));
     
  /* If a non-zero trynum finds a port that hasn't been discovered, the
	earlier packets(s) were probably dropped.  So we decrease our 
	numqueries_ideal, otherwise we increase it slightly */
  if (trynum == 0) {
    ss->numqueries_ideal = MIN(ss->numqueries_ideal + (ss->packet_incr/ss->numqueries_ideal), ss->max_width);
  } else  {
    if (!ss->alreadydecreasedqueries) {
      ss->alreadydecreasedqueries = 1;
      ss->numqueries_ideal *= ss->fallback_percent;
      if (ss->numqueries_ideal < 1.0) ss->numqueries_ideal = 1.0;
      if (o.debugging) 
	{ 
	  log_write(LOG_STDOUT, "Lost a packet, decreasing window to %d\n", (int) ss->numqueries_ideal);
	}
    }
  }

  if (current->state == PORT_TESTING)
    ss->numqueries_outstanding--;
     
  if (ntohl(rpc_pack->accept_stat) == PROG_UNAVAIL) {
    current->state = PORT_CLOSED;
    if (o.debugging > 1) {
      error("Port %hu/%s claims that it is not RPC service %li", 
	    rsi->rpc_current_port->portno, 
	    proto2ascii_uppercase(rsi->rpc_current_port->proto),  current->portno);
    }
    rsi->valid_responses_this_port++;
    return 0;
  } else if (ntohl(rpc_pack->accept_stat) == PROG_MISMATCH) {
    if (o.debugging > 1) {
      error("Port %hu/%s claims IT IS RPC service %li", rsi->rpc_current_port->portno, proto2ascii_uppercase(rsi->rpc_current_port->proto),  current->portno);
    }
    current->state = PORT_OPEN;
    rsi->rpc_status = RPC_STATUS_GOOD_PROG;
    rsi->rpc_program = current->portno;
    rsi->rpc_lowver = ntohl(rpc_pack->low_version);
    rsi->rpc_highver = ntohl(rpc_pack->high_version);
    rsi->valid_responses_this_port++;
    ss->numqueries_outstanding = 0;
    return 1;
  } else if (ntohl(rpc_pack->accept_stat) == SUCCESS) {
    error("Umm -- RPC returned success for bogus version -- thats OK I guess");
    rsi->rpc_status = RPC_STATUS_GOOD_PROG;
    rsi->rpc_program = current->portno;
    rsi->rpc_lowver = rsi->rpc_highver = 0;
    rsi->valid_responses_this_port++;
    ss->numqueries_outstanding = 0;
    return 1;
  } else {
    fatal("Illegal rpc accept_stat");
  }
  return 0;
}

void get_rpc_results(Target *target, struct portinfo *scan,
		     struct scanstats *ss, struct portinfolist *pil, 
                     struct rpcscaninfo *rsi) {
  int max_sd = -1;
  fd_set fds_r; 
  int sres;
  struct timeval tv;
  int res;
  static char readbuf[512];
  struct sockaddr_in from;
  recvfrom6_t fromlen = sizeof(struct sockaddr_in);
  char *current_msg;
  unsigned long current_msg_len;

  if ((udp_rpc_socket == -1 && tcp_rpc_socket == -1) || ss->numqueries_outstanding <= 0)
    return;

  FD_ZERO(&fds_r);

  if (udp_rpc_socket >= 0 && rsi->rpc_current_port->proto == IPPROTO_UDP) {
    FD_SET(udp_rpc_socket, &fds_r);
    max_sd = udp_rpc_socket;
  } else if (tcp_rpc_socket >= 0 && rsi->rpc_current_port->proto == IPPROTO_TCP) {
    FD_SET(tcp_rpc_socket, &fds_r);
    max_sd = tcp_rpc_socket;
  } else {
    error("Unable to find listening socket in %s", __func__);
    return;
  }


  while (ss->numqueries_outstanding > 0) {
    /* Insure there is no timeout ... */
    gettimeofday(&tv, NULL);
    if (target->timedOut(&tv))
      return;

    tv.tv_sec = target->to.timeout / 1000000;
    tv.tv_usec = target->to.timeout % 1000000;
    sres = select(max_sd + 1, &fds_r, NULL, NULL, &tv);
    if (!sres)
      break;
    if (sres == -1 && socket_errno() == EINTR)
      continue;
    if (udp_rpc_socket >= 0 && FD_ISSET(udp_rpc_socket, &fds_r)) {
      res = recvfrom(udp_rpc_socket, readbuf, sizeof(readbuf), 0, (struct sockaddr *) &from, &fromlen);

      if (res < 0) {
        /* Doh! */
        if (o.debugging || o.verbose)
          gh_perror("recvfrom in %s", __func__);
        ss->numqueries_outstanding = 0;
        rsi->rpc_status = RPC_STATUS_NOT_RPC;
        return;
      }
      if (o.debugging > 1)
        log_write(LOG_PLAIN, "Received %d byte UDP packet\n", res);
      /* Now we check that the response is from the expected host/port */
      if (from.sin_addr.s_addr != target->v4host().s_addr ||
          from.sin_port != htons(rsi->rpc_current_port->portno)) {
        if (o.debugging > 1) {
          log_write(LOG_PLAIN, "Received UDP packet from %d.%d.%d.%d/%hu when expecting packet from %d.%d.%d.%d/%hu\n", NIPQUAD(from.sin_addr.s_addr), ntohs(from.sin_port), NIPQUAD(target->v4host().s_addr), rsi->rpc_current_port->portno);
        }
        continue;
      }

      if (rpc_are_we_done(readbuf, res, target, scan, ss, pil, rsi) != 0) {
        return;
      }
    } else if (tcp_rpc_socket >= 0 && FD_ISSET(tcp_rpc_socket, &fds_r)) {
      do {     
        res = recv(tcp_rpc_socket, readbuf + tcp_readlen, sizeof(readbuf) - tcp_readlen, 0);
      } while(res == -1 && socket_errno() == EINTR);
      if (res <= 0) {
        if (o.debugging) {
          if (res == -1)
            gh_perror("Failed to read() from tcp rpc socket in %s", __func__);
          else {
            error("Lamer on port %u closed RPC socket on me in %s", rsi->rpc_current_port->portno, __func__);
          }
        }
        ss->numqueries_outstanding = 0;
        rsi->rpc_status = RPC_STATUS_NOT_RPC;
        return;
      }

      tcp_readlen += res;

      if (tcp_readlen < 28) {
        /* This is suspiciously small -- I'm assuming this is not the first
           part of a valid RPC packet */
        if (o.debugging > 1) {
          log_write(LOG_PLAIN, "Port %hu/%s labelled NON_RPC because tcp_readlen is %d (should be at least 28)\n", 
              rsi->rpc_current_port->portno, 
              proto2ascii_uppercase(rsi->rpc_current_port->proto), 
              (int) tcp_readlen);
        }
        ss->numqueries_outstanding = 0;
        rsi->rpc_status = RPC_STATUS_NOT_RPC;
        return;
      }
      /* I'm ignoring the multiple msg fragment possibility for now */
      current_msg_len = ntohl((*(unsigned long *)readbuf)) & 0x7FFFFFFF;

      if (current_msg_len > tcp_readlen - 4) {
        if (o.debugging > 1) {
          log_write(LOG_PLAIN, "Port %hu/%s labelled NON_RPC because current_msg_len is %li while tcp_readlen is %d\n",
              rsi->rpc_current_port->portno, 
              proto2ascii_uppercase(rsi->rpc_current_port->proto), 
              current_msg_len, (int) tcp_readlen);
        }
        ss->numqueries_outstanding = 0;
        rsi->rpc_status = RPC_STATUS_NOT_RPC;
        return;
      }
      current_msg = readbuf + 4;

      do {
        if (rpc_are_we_done(current_msg, current_msg_len, target, scan, ss, 
              pil, rsi) != 0) 
          return;

        current_msg += current_msg_len;
        if ((current_msg - readbuf) + 4UL < tcp_readlen) {       
          current_msg_len = ntohl(*(unsigned long *) current_msg) & 0x7FFFFFFF;
          current_msg += 4;
        } else {
          if ((unsigned long) (current_msg - readbuf) < tcp_readlen) {
            tcp_readlen -= current_msg - readbuf;
            memmove(readbuf, current_msg, tcp_readlen);
          } else tcp_readlen = 0;
          break;	   
        }

        if (current_msg_len < 24 || current_msg_len > 32) {
          ss->numqueries_outstanding = 0;
          if (o.debugging > 1) {
            log_write(LOG_PLAIN, "Port %hu/%s labelled NON_RPC because current_msg_len is %li\n", 
                rsi->rpc_current_port->portno, 
                proto2ascii_uppercase(rsi->rpc_current_port->proto), 
                current_msg_len);
          }
          rsi->rpc_status = RPC_STATUS_NOT_RPC;
          return;
        }

        if ((current_msg - readbuf) + current_msg_len > tcp_readlen) {
          tcp_readlen -= current_msg - readbuf;
          memmove(readbuf +4 , current_msg, tcp_readlen);
          *(unsigned long *)&readbuf = htonl(current_msg_len);
          tcp_readlen += 4;
          break;
        }
      } while(1);
    }
  }
  return;
}


void close_rpc_query_sockets() {
  if (udp_rpc_socket != -1) {
    close(udp_rpc_socket);
    udp_rpc_socket = -1;
  }

  if (tcp_rpc_socket != -1) {
    close(tcp_rpc_socket);
    tcp_rpc_socket = -1;
  }
}

