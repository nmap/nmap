
/***************************************************************************
 * dns_request_generation.cc -- Tests DNS request generation               *
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

#include "../nmap_dns.h"

#include <iostream>

#define TEST_INCR(pred,acc) \
if ( !(pred) ) \
{ \
  std::cout << "Test " << #pred << " failed at " << __FILE__ << ":" << __LINE__ << std::endl; \
  ++acc; \
}

int main()
{
  std::cout << "Testing nmap_dns" << std::endl;

  int ret = 0;
  std::string target = "scanme.nmap.org";
  DNS::RECORD_TYPE rt = DNS::A;
  const size_t buflen = 1500;
  u8 buf[buflen];
  size_t reqlen = DNS::Factory::buildSimpleRequest(target, rt, buf, buflen);
  
  DNS::Packet p;
  size_t plen = p.parseFromBuffer(buf, buflen);
  TEST_INCR(reqlen == plen, ret);

  DNS::Query * q = &*p.queries.begin();
  TEST_INCR(q->name == target, ret);
  TEST_INCR(q->record_class == DNS::CLASS_IN, ret);
  TEST_INCR(q->record_type == rt, ret);


  // This is a possible answere for an A query for scanme.nmap.org
  const char ipp[] = "45.33.32.156";
  const size_t answere_len = 49;
  const u8 answere_buf[] = { 0x92, 0xdc, // Trsnsaction ID
                       0x81, 0x80, // Flags
                       0x00, 0x01, // Questions count
                       0x00, 0x01, // Answers RRs count
                       0x00, 0x00, // Authorities RRs count
                       0x00, 0x00, // Additionals RRs count
                       0x06, // Label length <-- [12]
                       0x73, 0x63, 0x61, 0x6e, 0x6d, 0x65, // "scanme"
                       0x04, // Label length
                       0x6e, 0x6d, 0x61, 0x70, // "nmap"
                       0x03, // Label length
                       0x6f, 0x72, 0x67, // "org"
                       0x00, // Name terminator
                       0x00, 0x01, // A
                       0x00, 0x01, // CLASS_IN
                       0xc0, 0x0c, // Compressed name pointer to offset 12
                       0x00, 0x01, // A
                       0x00, 0x01, // CLASS_IN
                       0x00, 0x00, 0x0e, 0x0f, // TTL 3599
                       0x00, 0x04, // Record Length
                       0x2d, 0x21, 0x20, 0x9c }; // 45.33.32.156

  plen = p.parseFromBuffer(answere_buf, answere_len);
  TEST_INCR(answere_len == plen, ret);

  q = &*p.queries.begin();
  TEST_INCR(q->name == target, ret);
  TEST_INCR(q->record_class == DNS::CLASS_IN, ret);
  TEST_INCR(q->record_type == rt, ret );

  DNS::Answer * a = &*p.answers.begin();
  TEST_INCR(a->name == target, ret );
  TEST_INCR(a->record_class == DNS::CLASS_IN, ret);
  TEST_INCR(a->record_type == DNS::A, ret);
  TEST_INCR(a->ttl == 3599, ret)

  DNS::A_Record * ar = static_cast<DNS::A_Record *>(a->record);
  char ar_ipp[INET6_ADDRSTRLEN];
  sockaddr_storage_iptop(&ar->value, ar_ipp);
  TEST_INCR(!strcmp(ipp, ar_ipp), ret);

  const size_t ptr_answere_len = 72;
  std::string ptr_target;
  TEST_INCR(DNS::Factory::ipToPtr(ar->value, ptr_target), ret);
  TEST_INCR(ptr_target == "156.32.33.45.in-addr.arpa", ret);
  const u8 ptr_answere[] = { 0x08, 0xf2, // ID
                               0x81, 0x80, // Flags
                               0x00, 0x01, // Questions count
                               0x00, 0x01, // Answers RRs count
                               0x00, 0x00, // Authorities RRs count
                               0x00, 0x00, // Additionals RRs count
                               0x03, // Label length
                               0x31, 0x35, 0x36, // "156"
                               0x02, // Label length
                               0x33, 0x32, // "32"
                               0x02, // Label length
                               0x33, 0x33, // "33"
                               0x02, // Label length
                               0x34, 0x35, // "45"
                               0x07, // Label length
                               0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, // "in-addr"
                               0x04, // Label length
                               0x61, 0x72, 0x70, 0x61, // "arpa"
                               0x00, // Name terminator
                               0x00, 0x0c, // PTR
                               0x00, 0x01, // CLASS_IN
                               0xc0, 0x0c, // Compressed name pointer to offset 12
                               0x00, 0x0c, // PTR
                               0x00, 0x01, // CLASS_IN
                               0x00, 0x01, 0x51, 0x78, // TTL 86392
                               0x00, 0x11, // Record Length
                               0x06, // Label length
                               0x73, 0x63, 0x61, 0x6e, 0x6d, 0x65, // "scanme"
                               0x04, // Label length
                               0x6e, 0x6d, 0x61, 0x70, // "nmap"
                               0x03, // Label length
                               0x6f, 0x72, 0x67, // "org"
                               0x00 };  // Name terminator

  plen = p.parseFromBuffer(ptr_answere, ptr_answere_len);
  TEST_INCR(plen == ptr_answere_len, ret);
  TEST_INCR(p.id == 0x08f2, ret);
  TEST_INCR(p.flags == 0x8180, ret);
  TEST_INCR(p.queries.size() == 1, ret);
  TEST_INCR(p.answers.size() == 1, ret);

  q = &*p.queries.begin();
  TEST_INCR(q->name == ptr_target, ret);
  TEST_INCR(q->record_class == DNS::CLASS_IN, ret);
  TEST_INCR(q->record_type == DNS::PTR, ret);

  a = &*p.answers.begin();
  TEST_INCR(a->name == ptr_target, ret);
  TEST_INCR(a->record_class == DNS::CLASS_IN, ret);
  TEST_INCR(a->record_type == DNS::PTR, ret);
  TEST_INCR(a->length == 0x11, ret);
  TEST_INCR(a->ttl == 86392, ret);

  DNS::PTR_Record * r = static_cast<DNS::PTR_Record *>(a->record);
  TEST_INCR(r->value == target, ret);

  if(ret) std::cout << "Testing nmap_dns finished with errors" << std::endl;
  else std::cout << "Testing nmap_dns finished without errors" << std::endl;

  return ret; // 0 means ok
}
