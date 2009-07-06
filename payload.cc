
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

extern NmapOps o;

/*
  These payloads are taken from nmap-service-probes.

  The nmap-service-probes probe strings also happen to be Python strings, so you
  can convert them to this C strings with this program:

  s = eval('"' + raw_input().replace('"', '\\"') + '"')
  print '"' + "".join(c.isalnum() and c or "\\%03o" % ord(c) for c in s) + '"'
*/

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
  const char *payload;

  if (o.extra_payload_length > 0) {
    *length = o.extra_payload_length;
    return o.extra_payload;
  }

#define SET_PAYLOAD(p) do { *length = sizeof(p) - 1; payload = (p); } while (0)

  switch (dport) {
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
    /*
    case 1434:
      SET_PAYLOAD(payload_Sqlping);
      break;
    */
    default:
      SET_PAYLOAD(payload_null);
      break;
  }

  return payload;
}
