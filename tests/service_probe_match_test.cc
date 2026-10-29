/***************************************************************************
 * service_probe_match_test.cc -- Tests MariaDB unauthorized probe matches *
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

#include "../nmap.h"
#include "../service_scan.h"

#include <cstring>
#include <iostream>
#include <string>

namespace {
int failures = 0;

void expect(bool condition, const char *description) {
  if (!condition) {
    std::cout << "FAIL: " << description << std::endl;
    failures++;
  }
}

std::string error_packet(unsigned char sequence, unsigned int error_code,
                         const char *message) {
  const size_t message_len = std::strlen(message);
  const size_t payload_len = 3 + message_len;
  std::string packet(4 + payload_len, '\0');

  packet[0] = static_cast<char>(payload_len & 0xff);
  packet[1] = static_cast<char>((payload_len >> 8) & 0xff);
  packet[2] = static_cast<char>((payload_len >> 16) & 0xff);
  packet[3] = static_cast<char>(sequence);
  packet[4] = static_cast<char>(0xff);
  packet[5] = static_cast<char>(error_code & 0xff);
  packet[6] = static_cast<char>((error_code >> 8) & 0xff);
  std::memcpy(&packet[7], message, message_len);
  return packet;
}

void test_unauthorized(ServiceProbe *probe, unsigned char sequence) {
  const char *message =
      "Host '127.0.0.1' is not allowed to connect to this MariaDB server";
  const std::string packet = error_packet(sequence, 1130, message);
  const MatchDetails *match = probe->testMatch(
      reinterpret_cast<const u8 *>(packet.data()),
      static_cast<int>(packet.size()), 0);

  expect(match != NULL, "unauthorized response should match");
  if (match == NULL) {
    return;
  }
  expect(match->serviceName != NULL &&
             std::strcmp(match->serviceName, "mysql") == 0,
         "unauthorized response should match the mysql probe");
  expect(match->product != NULL &&
             std::strcmp(match->product, "MariaDB") == 0,
         "unauthorized response should identify MariaDB");
  expect(match->info != NULL &&
             std::strcmp(match->info, "unauthorized") == 0,
         "unauthorized response should report unauthorized");
  expect(match->version == NULL || match->version[0] == '\0',
         "unauthorized response should not report a version");
  expect(match->cpe_a != NULL &&
             std::strncmp(match->cpe_a, "cpe:/a:mariadb:mariadb",
                          sizeof("cpe:/a:mariadb:mariadb") - 1) == 0,
         "unauthorized response should report the MariaDB CPE");
}
}  // namespace

int main(int argc, char **argv) {
  const char *probes = argc > 1 ? argv[1] : "nmap-service-probes";
  AllProbes all_probes;
  parse_nmap_service_probe_file(&all_probes, probes);
  ServiceProbe *probe = all_probes.getProbeByName("NULL", IPPROTO_TCP);
  if (probe == NULL) {
    std::cout << "FAIL: NULL probe not found" << std::endl;
    return 1;
  }

  test_unauthorized(probe, 0x00);
  test_unauthorized(probe, 0x01);

  std::cout << "Ran 2 tests. " << failures << " failures." << std::endl;
  return failures == 0 ? 0 : 1;
}
