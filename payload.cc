
/***************************************************************************
 * payload.cc -- Retrieval of UDP payloads.                                *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2009 Insecure.Com LLC. Nmap is    *
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

#include "NmapOps.h"

#include "nbase.h"
#include "payload.h"

extern NmapOps o;

/*
  These payloads are taken from nmap-service-probes.

  The nmap-service-probes probe strings also happen to be Python strings, so you
  can convert them to this C strings with this program:

  s = eval('"' + raw_input().replace('"', '\\"') + '"')
  print '"' + "".join(c.isalnum() and c or "\\%03o" % ord(c) for c in s) + '"'

  These payloads are sent with every host discovery or port scan probe. Only
  include payloads that are unlikely to crash services, trip IDS alerts, or
  change state on the server.
*/

static const char payload_GenericLines[] = "\015\012\015\012";
static const char payload_DNSStatusRequest[] =
  "\000\000\020\000\000\000\000\000\000\000\000\000";
static const char payload_NTPRequest[] =
  "\343\000\004\372\000\001\000\000\000\001\000\000\000\000\000\000\000"
  "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
  "\000\000\000\000\000\000\305O\043Kq\261R\363";
static const char payload_NBTStat[] =
  "\200\360\000\020\000\001\000\000\000\000\000\000\040CKAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAA\000\000\041\000\001";
static const char payload_SNMPv3GetRequest[] =
  "0\072\002\001\0030\017\002\002Ji\002\003\000\377\343\004\001\004\002"
  "\001\003\004\0200\016\004\000\002\001\000\002\001\000\004\000\004"
  "\000\004\0000\022\004\000\004\000\240\014\002\0027\360\002\001\000"
  "\002\001\0000\000";

/* X Display Manager Control Protocol. Version 1, packet type Query (2), no
   authorization names. We expect a Willing or Unwilling packet in reply.
   http://cgit.freedesktop.org/xorg/doc/xorg-docs/plain/hardcopy/XDMCP/xdmcp.PS.gz */
static const char payload_xdmcp[] = "\000\001\000\002\000\001\000";

/* Internet Key Exchange version 1, phase 1 Main Mode. We offer every
   combination of (DES, 3DES) and (MD5, SHA) in the hope that one of them will
   be acceptable. Because we use a fixed cookie, we set the association lifetime
   to 1 second to reduce the chance that repeated probes will look like
   retransmissions (and therefore not get a response). This payload comes from
     ike-scan --lifetime 1 --cookie 0011223344556677 --trans=5,2,1,2 --trans=5,1,1,2 --trans=1,2,1,2 --trans=1,1,1,2
   We expect another phase 1 message in response. This payload works better with
   a source port of 500 or a randomized initiator cookie. */
static const char payload_ike[] =
  /* Initiator cookie 0x0011223344556677, responder cookie 0x0000000000000000. */
  "\000\021\042\063\104\125\146\167\000\000\000\000\000\000\000\000"
  /* Version 1, Main Mode, flags 0x00, message ID 0x00000000, length 192. */
  "\001\020\002\000\000\000\000\000\000\000\000\300"
  /* Security Association payload, length 164, IPSEC, IDENTITY. */
  "\000\000\000\244\000\000\000\001\000\000\000\001"
  /* Proposal 1, length 152, ISAKMP, 4 transforms. */
  "\000\000\000\230\001\001\000\004"
  /* Transform 1, 3DES-CBC, SHA, PSK, group 2. */
  "\003\000\000\044\001\001\000\000\200\001\000\005\200\002\000\002"
  "\200\003\000\001\200\004\000\002"
  "\200\013\000\001\000\014\000\004\000\000\000\001"
  /* Transform 2, 3DES-CBC, MD5, PSK, group 2. */
  "\003\000\000\044\002\001\000\000\200\001\000\005\200\002\000\001"
  "\200\003\000\001\200\004\000\002"
  "\200\013\000\001\000\014\000\004\000\000\000\001"
  /* Transform 3, DES-CBC, SHA, PSK, group 2. */
  "\003\000\000\044\003\001\000\000\200\001\000\001\200\002\000\002"
  "\200\003\000\001\200\004\000\002"
  "\200\013\000\001\000\014\000\004\000\000\000\001"
  /* Transform 4, DES-CBC, MD5, PSK, group 2. */
  "\000\000\000\044\004\001\000\000\200\001\000\001\200\002\000\001"
  "\200\003\000\001\200\004\000\002"
  "\200\013\000\001\000\014\000\004\000\000\000\001";

/* Routing Information Protocol version 1. Special-case request for the entire
   routing table (address family 0, address 0.0.0.0, metric 16). RFC 1058,
   section 3.4.1. */
static const char payload_rip[] =
  "\001\001\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
  "\000\000\000\000\000\000\000\020";

/* RADIUS Access-Request. This is a degenerate packet with no username or
   password; we expect an Access-Reject in response. The Identifier and Request
   Authenticator are both 0. It was generated by running
     echo 'User-Password = ""' | radclient <ip> auth ""
   and then manually stripping out the password.

   Section 2 of the RFC says "A request from a client for which the RADIUS
   server does not have a shared secret MUST be silently discarded." So this
   payload only works when the server is configured (or misconfigured) to know
   the scanning machine as a client. */
static const char payload_radius[] =
  "\001\000\000\024"
  "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000";

/* DNS Service Discovery (DNS-SD) service query, as used in Zeroconf.
   Transaction ID 0x0000, flags 0x0000, 1 question: PTR query for
   _services._dns-sd._udp.local. If the remote host supports DNS-SD it will send
   back a list of all its services. This is the same as a packet capture of
     dns-sd -B _services._dns-sd._udp .
   See section 9 of
   http://files.dns-sd.org/draft-cheshire-dnsext-dns-sd.txt. */
static const char payload_dns_sd[] =
  "\000\000\000\000\000\001\000\000\000\000\000\000"
  "\011_services\007_dns-sd\004_udp\005local\000\000\014\000\001";

/*
This one trips a Snort rule with SID 2049 ("MS-SQL ping attempt").
static const char payload_Sqlping[] = "\002";
*/

static const char payload_null[] = "";


/* Get a payload appropriate for the given UDP port. If --data-length was used,
   returns the global random payload. Otherwise, for certain selected ports a
   payload is returned, and for others a zero-length payload is returned. The
   length is returned through the length pointer. */
const char *get_udp_payload(u16 dport, size_t *length) {

  if (o.extra_payload_length > 0) {
    *length = o.extra_payload_length;
    return o.extra_payload;
  }
  else
    return udp_port2payload(dport, length);
}


/* Get a payload appropriate for the given UDP port. For certain selected 
   ports a payload is returned, and for others a zero-length payload is 
   returned. The length is returned through the length pointer. */
const char *udp_port2payload(u16 dport, size_t *length){
  const char *payload;
  
#define SET_PAYLOAD(p) do { *length = sizeof(p) - 1; payload = (p); } while (0)

  switch (dport) {
    case 7:
      SET_PAYLOAD(payload_GenericLines);
      break;
    case 53:
      SET_PAYLOAD(payload_DNSStatusRequest);
      break;
    case 123:
      SET_PAYLOAD(payload_NTPRequest);
      break;
    case 137:
      SET_PAYLOAD(payload_NBTStat);
      break;
    case 161:
      SET_PAYLOAD(payload_SNMPv3GetRequest);
      break;
    case 177:
      SET_PAYLOAD(payload_xdmcp);
      break;
    case 500:
      SET_PAYLOAD(payload_ike);
      break;
    case 520:
      SET_PAYLOAD(payload_rip);
      break;
    /*
    case 1434:
      SET_PAYLOAD(payload_Sqlping);
      break;
    */
    /* RFC 2865: "The early deployment of RADIUS was done using UDP port number
       1645, which conflicts with the "datametrics" service. The officially
       assigned port number for RADIUS is 1812. */
    case 1645:
    case 1812:
      SET_PAYLOAD(payload_radius);
      break;
    case 5353:
      SET_PAYLOAD(payload_dns_sd);
      break;
    default:
      SET_PAYLOAD(payload_null);
      break;
  }

  return payload;
    
}

