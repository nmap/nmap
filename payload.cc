
/***************************************************************************
 * payload.cc -- Retrieval of UDP payloads.                                *
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

/* $Id$ */

#include "nmap.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <map>

#include "NmapOps.h"
#include "nbase.h"
#include "payload.h"
#include "utils.h"
#include "nmap_error.h"
#include "scan_lists.h"
#include "service_scan.h"

extern NmapOps o;

/* The key for the payload lookup map is u16 dport. We can make it a u32 and
 * add proto later if needed. */

static std::map<u16, std::vector<ServiceProbe *> > portPayloads;

void init_payloads(void) {
  static bool payloads_loaded = false;

  if (payloads_loaded)
    return;

  AllProbes *AP = AllProbes::service_scan_init();
  for (std::vector<ServiceProbe *>::const_iterator it = AP->probes.begin();
      it != AP->probes.end(); it++) {
    ServiceProbe *current_probe = *it;
    if (current_probe->getProbeProtocol() == IPPROTO_UDP && !current_probe->notForPayload) {
      for (std::vector<u16>::const_iterator pt = current_probe->probablePortsBegin();
          pt != current_probe->probablePortsEnd(); pt++) {
        std::vector<ServiceProbe *> &portPayloadVector = portPayloads[*pt];
        portPayloadVector.push_back(current_probe);
        if (portPayloadVector.size() > MAX_PAYLOADS_PER_PORT) {
          fatal("Number of UDP payloads for port %u exceeds the limit of %u.\n", *pt, MAX_PAYLOADS_PER_PORT);
        }
      }
    }
  }
  payloads_loaded = true;
}

/* Get a payload appropriate for the given UDP port. For certain selected ports
   a payload is returned, and for others a zero-length payload is returned. The
   length is returned through the length pointer. */
static const u8 *udp_port2payload(u16 dport, int *length, u8 index) {
  const u8 *payload = NULL;
  std::map<u16, std::vector<ServiceProbe *> >::const_iterator portPayloadIterator;
  int portPayloadVectorSize;

  *length = 0;
  portPayloadIterator = portPayloads.find(dport);

  if (portPayloadIterator != portPayloads.end()) {
    const std::vector<ServiceProbe *>& portPayloadVector = portPayloadIterator->second;
    portPayloadVectorSize = portPayloadVector.size();
    assert(portPayloadVectorSize > 0);

    const ServiceProbe *SP = portPayloadVector[index % portPayloadVectorSize];
    payload = SP->getProbeString(length);

  }
  return payload;
}

/* Get a payload appropriate for the given UDP port. If --data-length was used,
   returns the global random payload. Otherwise, for certain selected ports a
   payload is returned, and for others a zero-length payload is returned. The
   length is returned through the length pointer. */
const u8 *get_udp_payload(u16 dport, int *length, u8 index) {
  if (o.extra_payload != NULL) {
    *length = o.extra_payload_length;
    return (u8 *) o.extra_payload;
  } else {
    return udp_port2payload(dport, length, index);
  }
}

u8 udp_payload_count(u16 dport) {
  std::map<u16, std::vector<ServiceProbe *> >::const_iterator portPayloadIterator;
  size_t portPayloadVectorSize = 0;

  portPayloadIterator = portPayloads.find(dport);

  if (portPayloadIterator != portPayloads.end()) {
    portPayloadVectorSize = portPayloadIterator->second.size();
  }

  return portPayloadVectorSize;
}

const struct MatchDetails *payload_service_match(u16 dport, const u8 *buf, int buflen) {
  std::map<u16, std::vector<ServiceProbe *> >::const_iterator portPayloadIterator;

  portPayloadIterator = portPayloads.find(dport);
  if (portPayloadIterator != portPayloads.end()) {
    const std::vector<ServiceProbe *>& portPayloadVector = portPayloadIterator->second;
    // We don't know which payload triggered this, since we send all at once
    // with the same source port.
    for (std::vector<ServiceProbe *>::const_iterator sp = portPayloadVector.begin();
        sp != portPayloadVector.end(); sp++) {
      ServiceProbe *probe = *sp;
      const struct MatchDetails *MD = NULL;
      for (int fb = 0; probe->fallbacks[fb] != NULL; fb++) {
        MD = probe->fallbacks[fb]->testMatch(buf, buflen, 0);
        if (MD)
          return MD;
      }
    }
  }
  return NULL;
}
