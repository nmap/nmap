
/***************************************************************************
 * common_modified.cc --  This file holds all those functions and classes  *
 * that have been reused from Nmap's code but that needed to be modified   *
 * in order to reuse them.                                                 *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2026 Nmap Software LLC ("The Nmap
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
#include "nping.h"
#include "common_modified.h"
#include "output.h"

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
