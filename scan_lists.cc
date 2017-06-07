/***************************************************************************
 * scan_lists.cc -- Structures and functions for lists of ports to scan    *
 * and scan types                                                          *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2017 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed Nmap technology into proprietary      *
 * software, we sell alternative licenses (contact sales@nmap.com).        *
 * Dozens of software vendors already license Nmap technology such as      *
 * host discovery, port scanning, OS detection, version detection, and     *
 * the Nmap Scripting Engine.                                              *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, the Nmap Project grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * The Nmap Project has permission to redistribute Npcap, a packet         *
 * capturing driver and library for the Microsoft Windows platform.        *
 * Npcap is a separate work with it's own license rather than this Nmap    *
 * license.  Since the Npcap license does not permit redistribution        *
 * without special permission, our Nmap Windows binary packages which      *
 * contain Npcap may not be redistributed without special permission.      *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify            *
 * otherwise) that you are offering the Nmap Project the unlimited,        *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because     *
 * the inability to relicense code has caused devastating problems for     *
 * other Free Software projects (such as KDE and NASM).  We also           *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/

/* Convert a string like "-100,n*tp,200-1024,3000-4000,[60000-]" into an array
 * of port numbers. Note that one trailing comma is OK -- this is actually
 * useful for machine generated lists
 *
 * Fyodor - Wrote original
 * William McVey - Added T:, U:, P: directives
 * Doug Hoyte - Added [], name lookups, and wildcard expansion
 *
 * getpts() handles []
 * Any port ranges included inside square brackets will have all
 * their ports looked up in nmap-services or nmap-protocols
 * and will only be included if they are found.
 * Returns a scan_list* with all the ports that should be scanned.
 *
 * getpts() handles service/protocol name lookups and wildcard expansion.
 * The service name can be specified instead of the port number.
 * For example, "ssh" can be used instead of "22". You can use wildcards
 * like "*" and "?". See the function wildtest() for the exact details.
 * For example,
 *
 * nmap -p http* host
 *
 * Will scan http (80), http-mgmt (280), http-proxy (8080), https (443), etc.
 *
 * Matching is case INsensitive but the first character in a match MUST
 * be lowercase so it doesn't conflict with the T:, U:, and P: directives.
 *
 * getpts() is unable to match service names that start with a digit
 * like 3com-tsmux (106/udp). Use a pattern like "?com-*" instead.
 *
 * BE CAREFUL ABOUT SHELL EXPANSIONS!!!
 * If you are trying to match the services nmsp (537/tcp) and nms (1429/tcp)
 * and you execute the command
 *
 * ./nmap -p nm* host
 *
 * You will see
 *
 * Found no matches for the service mask 'nmap' and your specified protocols
 * QUITTING!
 *
 * This is because nm* was expanded to the name of the binary file nmap in
 * the current directory by your shell. When unsure, quote your port strings
 * to be safe:
 *
 * ./nmap -p 'nm*' host
 *
 * getpts() is smart enough to keep the T: U: and P: directives nested
 * and working in a logical manner. For instance,
 *
 * nmap -sTU -p [U:1025-],1-1024 host
 *
 * Will scan UDP ports 1025 and up that are found in the service file
 * and all TCP/UDP ports below <= 1024. Notice that the U doesn't affect
 * the outer part of the port expression. It's "closed".
 */

#include "scan_lists.h"
#include "nmap_error.h"
#include "NmapOps.h"
#include "protocols.h"
#include "services.h"
#include <nbase.h>

extern NmapOps o;  /* option structure */

static void getpts_aux(const char *origexpr, int nested, u8 *porttbl, int range_type,
                       int *portwarning, bool change_range_type = true);

void getpts(const char *origexpr, struct scan_lists *ports) {
  u8 *porttbl;
  int range_type = 0;
  int portwarning = 0;
  int i, tcpi, udpi, sctpi, proti;

  if (o.TCPScan())
    range_type |= SCAN_TCP_PORT;
  if (o.UDPScan())
    range_type |= SCAN_UDP_PORT;
  if (o.SCTPScan())
    range_type |= SCAN_SCTP_PORT;
  if (o.ipprotscan)
    range_type |= SCAN_PROTOCOLS;
  if (o.noportscan && o.exclude_portlist) { // We want to exclude from ping scans in this case but we take port list normally and then removepts() handles it
    range_type |= SCAN_TCP_PORT;
    range_type |= SCAN_UDP_PORT;
    range_type |= SCAN_SCTP_PORT;
  }

  porttbl = (u8 *) safe_zalloc(65536);

  getpts_aux(origexpr,      // Pass on the expression
             0,             // Don't start off nested
             porttbl,       // Our allocated port table
             range_type,    // Defaults to TCP/UDP/SCTP/Protos
             &portwarning); // No, we haven't warned them about dup ports yet

  ports->tcp_count = 0;
  ports->udp_count = 0;
  ports->sctp_count = 0;
  ports->prot_count = 0;
  for (i = 0; i <= 65535; i++) {
    if (porttbl[i] & SCAN_TCP_PORT)
      ports->tcp_count++;
    if (porttbl[i] & SCAN_UDP_PORT)
      ports->udp_count++;
    if (porttbl[i] & SCAN_SCTP_PORT)
      ports->sctp_count++;
    if (porttbl[i] & SCAN_PROTOCOLS && i < 256)
      ports->prot_count++;
  }

  if (range_type != 0 && 0 == (ports->tcp_count + ports->udp_count + ports->sctp_count + ports->prot_count))
    fatal("No ports specified -- If you really don't want to scan any ports use ping scan...");

  if (ports->tcp_count) {
    ports->tcp_ports = (unsigned short *)safe_zalloc(ports->tcp_count * sizeof(unsigned short));
  }
  if (ports->udp_count) {
    ports->udp_ports = (unsigned short *)safe_zalloc(ports->udp_count * sizeof(unsigned short));
  }
  if (ports->sctp_count) {
    ports->sctp_ports = (unsigned short *)safe_zalloc(ports->sctp_count * sizeof(unsigned short));
  }
  if (ports->prot_count) {
    ports->prots = (unsigned short *)safe_zalloc(ports->prot_count * sizeof(unsigned short));
  }

  for (i = tcpi = udpi = sctpi = proti = 0; i <= 65535; i++) {
    if (porttbl[i] & SCAN_TCP_PORT)
      ports->tcp_ports[tcpi++] = i;
    if (porttbl[i] & SCAN_UDP_PORT)
      ports->udp_ports[udpi++] = i;
    if (porttbl[i] & SCAN_SCTP_PORT)
      ports->sctp_ports[sctpi++] = i;
    if (porttbl[i] & SCAN_PROTOCOLS && i < 256)
      ports->prots[proti++] = i;
  }

  free(porttbl);
}

/* This function is like getpts except it only allocates space for and stores
  values into one unsigned short array, instead of an entire scan_lists struct
  For that reason, T:, U:, S: and P: restrictions are not allowed and only one
  bit in range_type may be set. */
void getpts_simple(const char *origexpr, int range_type,
                   unsigned short **list, int *count) {
  u8 *porttbl;
  int portwarning = 0;
  int i, j;

  /* Make sure that only one bit in range_type is set (or that range_type is 0,
     which is useless but not incorrect). */
  assert((range_type & (range_type - 1)) == 0);

  porttbl = (u8 *) safe_zalloc(65536);

  /* Get the ports but do not allow changing the type with T:, U:, or P:. */
  getpts_aux(origexpr, 0, porttbl, range_type, &portwarning, false);

  /* Count how many are set. */
  *count = 0;
  for (i = 0; i <= 65535; i++) {
    if (porttbl[i] & range_type)
      (*count)++;
  }

  if (*count == 0) {
    free(porttbl);
    return;
  }

  *list = (unsigned short *) safe_zalloc(*count * sizeof(unsigned short));

  /* Fill in the list. */
  for (i = 0, j = 0; i <= 65535; i++) {
    if (porttbl[i] & range_type)
      (*list)[j++] = i;
  }

  free(porttbl);
}

/* removepts() takes a port specification and removes any matching ports
  from the given scan_lists struct. */

static int remaining_ports(unsigned short int *ports, int count, unsigned short int *exclude_ports, int exclude_count, const char *type = "");

void removepts(const char *expr, struct scan_lists * ports) {
  static struct scan_lists exclude_ports;

  if (!expr)
    return;

  getpts(expr, &exclude_ports);

  #define SUBTRACT_PORTS(type,excludetype) \
    ports->type##_count = remaining_ports(ports->type##_ports, \
                                          ports->type##_count, \
                                          exclude_ports.excludetype##_ports, \
                                          exclude_ports.excludetype##_count, \
                                          #type)

  SUBTRACT_PORTS(tcp, tcp);
  SUBTRACT_PORTS(udp, udp);
  SUBTRACT_PORTS(sctp, sctp);
  SUBTRACT_PORTS(syn_ping, tcp);
  SUBTRACT_PORTS(ack_ping, tcp);
  SUBTRACT_PORTS(udp_ping, udp);
  SUBTRACT_PORTS(sctp_ping, sctp);

  #define prot_ports prots
  SUBTRACT_PORTS(prot, prot);
  SUBTRACT_PORTS(proto_ping, prot);
  #undef prot_ports

  #undef SUBTRACT_PORTS

  free_scan_lists(&exclude_ports);
}

/* This function returns the number of ports that remain after the excluded ports
  are removed from the ports. It places these ports at the start of the ports array. */
static int remaining_ports(unsigned short int *ports, int count, unsigned short int *exclude_ports, int exclude_count, const char *type) {
  static bool has_been_excluded[65536];
  int i, j;

  if (count == 0 || exclude_count == 0)
    return count;

  if (o.debugging > 1)
    log_write(LOG_STDOUT, "Removed %s ports: ", type);

  for (i = 0; i < 65536; i++)
    has_been_excluded[i] = false;
  for (i = 0; i < exclude_count; i++)
    has_been_excluded[exclude_ports[i]] = true;
  for (i = 0, j = 0; i < count; i++)
    if (!has_been_excluded[ports[i]])
      ports[j++] = ports[i];
    else if (o.debugging > 1)
      log_write(LOG_STDOUT, "%d ", ports[i]);

  if (o.debugging > 1) {
    if (count-j) {
      log_write(LOG_STDOUT, "\n");
    } else {
      log_write(LOG_STDOUT, "None\n");
    }
  }
  if (o.debugging && count-j) {
    log_write(LOG_STDOUT, "Removed %d %s ports that would have been considered for scanning otherwise.\n", count-j, type);
  }

  return j;
}

/* getpts() and getpts_simple() (see above) are wrappers for this function */

static void getpts_aux(const char *origexpr, int nested, u8 *porttbl, int range_type, int *portwarning, bool change_range_type) {
  long rangestart = -2343242, rangeend = -9324423;
  const char *current_range;
  char *endptr;
  char servmask[128];  // A protocol name can be up to 127 chars + nul byte
  int i;

  /* An example of proper syntax to use in error messages. */
  const char *syntax_example;
  if (change_range_type)
    syntax_example = "-100,200-1024,T:3000-4000,U:60000-";
  else
    syntax_example = "-100,200-1024,3000-4000,60000-";

  current_range = origexpr;
  do {
    while (isspace((int) (unsigned char) *current_range))
      current_range++; /* I don't know why I should allow spaces here, but I will */

    if (change_range_type) {
      if (*current_range == 'T' && *(current_range+1) == ':') {
        current_range += 2;
        range_type = SCAN_TCP_PORT;
        continue;
      }
      if (*current_range == 'U' && *(current_range+1) == ':') {
        current_range += 2;
        range_type = SCAN_UDP_PORT;
        continue;
      }
      if (*current_range == 'S' && *(current_range+1) == ':') {
        current_range += 2;
        range_type = SCAN_SCTP_PORT;
        continue;
      }
      if (*current_range == 'P' && *(current_range+1) == ':') {
        current_range += 2;
        range_type = SCAN_PROTOCOLS;
        continue;
      }
    }

    if (*current_range == '[') {
      if (nested)
        fatal("Can't nest [] brackets in port/protocol specification");

      getpts_aux(++current_range, 1, porttbl, range_type, portwarning);

      // Skip past the ']'. This is OK because we can't nest []s
      while (*current_range != ']' && *current_range != '\0')
        current_range++;
      if (*current_range == ']')
        current_range++;

      // Skip over a following ',' so we're ready to keep parsing
      if (*current_range == ',')
        current_range++;

      continue;
    } else if (*current_range == ']') {
      if (!nested)
        fatal("Unexpected ] character in port/protocol specification");

      return;
    } else if (*current_range == '-') {
      if (range_type & SCAN_PROTOCOLS)
        rangestart = 0;
      else
        rangestart = 1;
    } else if (isdigit((int) (unsigned char) *current_range)) {
      rangestart = strtol(current_range, &endptr, 10);
      if (range_type & SCAN_PROTOCOLS) {
        if (rangestart < 0 || rangestart > 255)
          fatal("Protocols specified must be between 0 and 255 inclusive");
      } else {
        if (rangestart < 0 || rangestart > 65535)
          fatal("Ports specified must be between 0 and 65535 inclusive");
      }
      current_range = endptr;
      while (isspace((int) (unsigned char) *current_range)) current_range++;
    } else if (islower((int) (unsigned char) *current_range) || *current_range == '*' || *current_range == '?') {
      i = 0;

      while (*current_range && !isspace((int) (unsigned char) *current_range) && *current_range != ',' && *current_range != ']') {
        servmask[i++] = *(current_range++);
        if (i >= ((int)sizeof(servmask) - 1))
          fatal("A service mask in the port/protocol specification is either malformed or too long");
      }

      if (*current_range && *current_range != ']') current_range++; // We want the '] character to be picked up on the next pass
      servmask[i] = '\0'; // Finish the string

      i = addportsfromservmask(servmask, porttbl, range_type);
      if (range_type & SCAN_PROTOCOLS)
        i += addprotocolsfromservmask(servmask, porttbl);

      if (i == 0)
        fatal("Found no matches for the service mask '%s' and your specified protocols", servmask);

      continue;

    } else {
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
        if (range_type & SCAN_PROTOCOLS)
          rangeend = 255;
        else
          rangeend = 65535;
      } else if (isdigit((int) (unsigned char) *current_range)) {
        rangeend = strtol(current_range, &endptr, 10);
        if (range_type & SCAN_PROTOCOLS) {
          if (rangeend < 0 || rangeend > 255)
            fatal("Protocols specified must be between 0 and 255 inclusive");
        } else {
          if (rangeend < 0 || rangeend > 65535)
            fatal("Ports specified must be between 0 and 65535 inclusive");
        }
        current_range = endptr;
      } else {
        fatal("Error #486: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
      }
      if (rangeend < rangestart) {
        fatal("Your %s range %ld-%ld is backwards. Did you mean %ld-%ld?",
              (range_type & SCAN_PROTOCOLS) ? "protocol" : "port",
              rangestart, rangeend, rangeend, rangestart);
      }
    } else {
      fatal("Error #487: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }

    /* Now I have a rangestart and a rangeend, so I can add these ports */
    while (rangestart <= rangeend) {
      if (porttbl[rangestart] & range_type) {
        if (!(*portwarning)) {
          error("WARNING: Duplicate port number(s) specified.  Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm).");
          (*portwarning)++;
        }
      } else {
        if (nested) {
          if ((range_type & SCAN_TCP_PORT) &&
              nmap_getservbyport(rangestart, "tcp")) {
            porttbl[rangestart] |= SCAN_TCP_PORT;
          }
          if ((range_type & SCAN_UDP_PORT) &&
              nmap_getservbyport(rangestart, "udp")) {
            porttbl[rangestart] |= SCAN_UDP_PORT;
          }
          if ((range_type & SCAN_SCTP_PORT) &&
              nmap_getservbyport(rangestart, "sctp")) {
            porttbl[rangestart] |= SCAN_SCTP_PORT;
          }
          if ((range_type & SCAN_PROTOCOLS) &&
              nmap_getprotbynum(rangestart)) {
            porttbl[rangestart] |= SCAN_PROTOCOLS;
          }
        } else {
          porttbl[rangestart] |= range_type;
        }
      }
      rangestart++;
    }

    /* Find the next range */
    while (isspace((int) (unsigned char) *current_range)) current_range++;

    if (*current_range == ']') {
      if (!nested)
        fatal("Unexpected ] character in port/protocol specification");
      return;
    }

    if (*current_range && *current_range != ',') {
      fatal("Error #488: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }
    if (*current_range == ',')
      current_range++;
  } while (current_range && *current_range);

}
