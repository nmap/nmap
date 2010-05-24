
/***************************************************************************
 * payload.cc -- Retrieval of UDP payloads.                                *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2010 Insecure.Com LLC. Nmap is    *
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
  These payloads are sent with every host discovery or port scan probe. Only
  include payloads that are unlikely to crash services, trip IDS alerts, or
  change state on the server.

  Some of them are taken from nmap-service-probes.
*/

static const char payload_GenericLines[] = "\x0D\x0A\x0D\x0A";
static const char payload_DNSStatusRequest[] =
  "\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00";
static const char payload_RPCCheck[] =
  "\x72\xFE\x1D\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xA0"
  "\x00\x01\x97\x7C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00";
static const char payload_NTPRequest[] =
  "\xE3\x00\x04\xFA\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\xC5\x4F\x23\x4B\x71\xB1\x52\xF3";
static const char payload_NBTStat[] =
  "\x80\xF0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"
  "\x20" "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01";
static const char payload_SNMPv3GetRequest[] =
  "\x30\x3A\x02\x01\x03\x30\x0F\x02\x02\x4A\x69\x02\x03\x00\xFF\xE3"
  "\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0E\x04\x00\x02\x01\x00\x02"
  "\x01\x00\x04\x00\x04\x00\x04\x00\x30\x12\x04\x00\x04\x00\xA0\x0C"
  "\x02\x02\x37\xF0\x02\x01\x00\x02\x01\x00\x30\x00";
static const char payload_serialnumberd[] = "SNQUERY: 127.0.0.1:AAAAAA:xsvr";

/* X Display Manager Control Protocol. Version 1, packet type Query (2), no
   authorization names. We expect a Willing or Unwilling packet in reply.
   http://cgit.freedesktop.org/xorg/doc/xorg-docs/plain/hardcopy/XDMCP/xdmcp.PS.gz */
static const char payload_xdmcp[] = "\x00\x01\x00\x02\x00\x01\x00";

/*
This one trips a Snort rule with SID 2049 ("MS-SQL ping attempt").
static const char payload_Sqlping[] = "\x02";
*/

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
  "\x00\x11\x22\x33\x44\x55\x66\x77\x00\x00\x00\x00\x00\x00\x00\x00"
  /* Version 1, Main Mode, flags 0x00, message ID 0x00000000, length 192. */
  "\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\xC0"
  /* Security Association payload, length 164, IPSEC, IDENTITY. */
  "\x00\x00\x00\xA4\x00\x00\x00\x01\x00\x00\x00\x01"
  /* Proposal 1, length 152, ISAKMP, 4 transforms. */
  "\x00\x00\x00\x98\x01\x01\x00\x04"
  /* Transform 1, 3DES-CBC, SHA, PSK, group 2. */
  "\x03\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02"
  "\x80\x03\x00\x01\x80\x04\x00\x02"
  "\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01"
  /* Transform 2, 3DES-CBC, MD5, PSK, group 2. */
  "\x03\x00\x00\x24\x02\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x01"
  "\x80\x03\x00\x01\x80\x04\x00\x02"
  "\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01"
  /* Transform 3, DES-CBC, SHA, PSK, group 2. */
  "\x03\x00\x00\x24\x03\x01\x00\x00\x80\x01\x00\x01\x80\x02\x00\x02"
  "\x80\x03\x00\x01\x80\x04\x00\x02"
  "\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01"
  /* Transform 4, DES-CBC, MD5, PSK, group 2. */
  "\x00\x00\x00\x24\x04\x01\x00\x00\x80\x01\x00\x01\x80\x02\x00\x01"
  "\x80\x03\x00\x01\x80\x04\x00\x02"
  "\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01";

/* Routing Information Protocol version 1. Special-case request for the entire
   routing table (address family 0, address 0.0.0.0, metric 16). RFC 1058,
   section 3.4.1. */
static const char payload_rip[] =
  "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x10";

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
  "\x01\x00\x00\x14"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

/* NFS version 2, RFC 1831. XID 0x00000000, program 100003 (NFS), procedure
   NFSPROC_NULL (does nothing, see section 2.2.1), null authentication (see
   section 9.1). */
static const char payload_nfs[] =
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xA3"
  "\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00";

/* DNS Service Discovery (DNS-SD) service query, as used in Zeroconf.
   Transaction ID 0x0000, flags 0x0000, 1 question: PTR query for
   _services._dns-sd._udp.local. If the remote host supports DNS-SD it will send
   back a list of all its services. This is the same as a packet capture of
     dns-sd -B _services._dns-sd._udp .
   See section 9 of
   http://files.dns-sd.org/draft-cheshire-dnsext-dns-sd.txt. */
static const char payload_dns_sd[] =
  "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
  "\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0C\x00\x01";

/* Amanda backup service noop request. I think that this does nothing on the
   server but only asks it to send back its feature list. In reply we expect an
   ACK or (more likely) an ERROR. I couldn't find good online documentation of
   the Amanda network protocol. There is parsing code in the Amanda source at
   common-src/security-util.c. This is based on a packet capture of
     amcheck <config> <host> */
static const char payload_amanda[] =
  "Amanda 2.6 REQ HANDLE 000-00000000 SEQ 0\n"
  "SERVICE noop\n";

/* Citrix MetaFrame application browser service
   Original idea from http://sh0dan.org/oldfiles/hackingcitrix.html  
   Payload contents copied from Wireshark capture of Citrix Program 
   Neighborhood client application.  The application uses this payload to
   locate Citrix servers on the local network.  Response to this probe is 
   a 48 byte UDP payload as shown here:

   0000   30 00 02 31 02 fd a8 e3 02 00 06 44 c0 a8 80 55
   0010   00 00 00 00 00 00 00 00 00 00 00 00 02 00 06 44
   0020   c0 a8 80 56 00 00 00 00 00 00 00 00 00 00 00 00

   The first 12 bytes appear to be the same in all responses.

   Bytes 0x00 appears to be a packet length field
   Bytes 0x0C - 0x0F are the IP address of the server
   Bytes 0x10 - 0x13 may vary, 0x14 - 0x1F do not appear to
   Bytes 0x20 - 0x23 are the IP address of the primary system in a server farm
   configuration 
   Bytes 0x24 - 0x27 can vary, 0x28 - 0x2F do not appear to  */
static const char payload_citrix[] =
  "\x1e\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00"
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

/* Quake 2 and Quake 3 game servers (and servers of derived games like Nexuiz).
   Gets game information from the server (see probe responses in
   nmap-service-probes). */
static const char payload_quake2[] = "\xff\xff\xff\xffstatus";
static const char payload_quake3[] = "\xff\xff\xff\xffgetstatus";

static const char payload_null[] = "";


/* Get a payload appropriate for the given UDP port. If --data-length was used,
   returns the global random payload. Otherwise, for certain selected ports a
   payload is returned, and for others a zero-length payload is returned. The
   length is returned through the length pointer. */
const char *get_udp_payload(u16 dport, size_t *length) {

  if (o.extra_payload != NULL) {
    *length = o.extra_payload_length;
    return o.extra_payload;
  } else {
    return udp_port2payload(dport, length);
  }
}

/* Get a payload appropriate for the given UDP port. For certain selected ports
   a payload is returned, and for others a zero-length payload is returned. The
   length is returned through the length pointer. */
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
    case 111:
      SET_PAYLOAD(payload_RPCCheck);
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
    case 626:
      SET_PAYLOAD(payload_serialnumberd);
      break;
    /*
    case 1434:
      SET_PAYLOAD(payload_Sqlping);
      break;
    */
    case 1604:
      SET_PAYLOAD(payload_citrix);
      break;
    /* RFC 2865: "The early deployment of RADIUS was done using UDP port number
       1645, which conflicts with the "datametrics" service. The officially
       assigned port number for RADIUS is 1812. */
    case 1645:
    case 1812:
      SET_PAYLOAD(payload_radius);
      break;
    case 2049:
      SET_PAYLOAD(payload_nfs);
      break;
    case 5353:
      SET_PAYLOAD(payload_dns_sd);
      break;
    case 10080:
      SET_PAYLOAD(payload_amanda);
      break;
    /* These servers are commonly run on a base port or a few port numbers
       higher. */
    case 27910: case 27911: case 27912: case 27913: case 27914:
      SET_PAYLOAD(payload_quake2);
      break;
    case 26000: case 26001: case 26002: case 26003: case 26004: /* Nexuiz */
    case 27960: case 27961: case 27962: case 27963: case 27964: /* Several */
    case 30720: case 30721: case 30722: case 30723: case 30724: /* Tremulous */
    case 44400: /* Warsow */
      SET_PAYLOAD(payload_quake3);
      break;
    default:
      SET_PAYLOAD(payload_null);
      break;
  }

  return payload;
}
