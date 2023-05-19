/***************************************************************************
 * nmap_dns.h -- Handles parallel reverse DNS resolution for target IPs    *
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

#ifndef NMAP_DNS_H
#define NMAP_DNS_H

class Target;

#include <nbase.h>

#include <string>
#include <list>

#include <algorithm>
#include <sstream>

#define DNS_LABEL_MAX_LENGTH 63
#define DNS_NAME_MAX_LENGTH 255

namespace DNS
{

#define DNS_CHECK_ACCUMLATE(accumulator, tmp, exp) \
  do { tmp = exp; if(tmp < 1) return 0 ; accumulator += tmp;} while(0)

#define DNS_CHECK_UPPER_BOUND(accumulator, max)\
  do { if(accumulator > max) return 0; } while(0)

#define DNS_HAS_FLAG(v,flag) ((v&flag)==flag)

#define DNS_HAS_ERR(v, err) ((v&DNS::ERR_ALL)==err)

typedef enum
{
  ID = 0,
  FLAGS_OFFSET = 2,
  QDCOUNT = 4,
  ANCOUNT = 6,
  NSCOUNT = 8,
  ARCOUNT = 10,
  DATA = 12
} HEADER_OFFSET;

typedef enum {
  ERR_ALL = 0x0007,
  CHECKING_DISABLED = 0x0010,
  AUTHENTICATED_DATA = 0x0020,
  ZERO = 0x0070,
  RECURSION_AVAILABLE = 0x0080,
  RECURSION_DESIRED = 0x0100,
  TRUNCATED = 0x0200,
  AUTHORITATIVE_ANSWER = 0x0400,
  OP_STANDARD_QUERY = 0x0000,
  OP_INVERSE_QUERY = 0x0800, // Obsoleted in RFC 3425
  OP_SERVER_STATUS = 0x1000,
  RESPONSE = 0x8000
} FLAGS;

typedef enum {
  ERR_NO = 0x0000,
  ERR_FORMAT = 0x0001,
  ERR_SERVFAIL = 0x0002,
  ERR_NAME = 0x0003,
  ERR_NOT_IMPLEMENTED = 0x0004,
  ERR_REFUSED = 0x0005,
} ERRORS;

typedef enum {
  A = 1,
  CNAME = 5,
  PTR = 12,
  AAAA = 28,
} RECORD_TYPE;

typedef enum {
  CLASS_IN = 1
} RECORD_CLASS;

const u8 COMPRESSED_NAME = 0xc0;

#define C_IPV4_PTR_DOMAIN ".in-addr.arpa"
#define C_IPV6_PTR_DOMAIN ".ip6.arpa"
const std::string IPV4_PTR_DOMAIN = C_IPV4_PTR_DOMAIN;
const std::string IPV6_PTR_DOMAIN = C_IPV6_PTR_DOMAIN;

class Factory
{
public:
  static u16 progressiveId;
  static bool ipToPtr(const sockaddr_storage &ip, std::string &ptr);
  static bool ptrToIp(const std::string &ptr, sockaddr_storage &ip);
  static size_t buildSimpleRequest(const std::string &name, RECORD_TYPE rt, u8 *buf, size_t maxlen);
  static size_t buildReverseRequest(const sockaddr_storage &ip, u8 *buf, size_t maxlen);
  static size_t putUnsignedShort(u16 num, u8 *buf, size_t offset, size_t maxlen);
  static size_t putDomainName(const std::string &name, u8 *buf, size_t offset, size_t maxlen);
  static size_t parseUnsignedShort(u16 &num, const u8 *buf, size_t offset, size_t maxlen);
  static size_t parseUnsignedInt(u32 &num, const u8 *buf, size_t offset, size_t maxlen);
  static size_t parseDomainName(std::string &name, const u8 *buf, size_t offset, size_t maxlen);
};

class Record
{
public:
  virtual Record * clone() = 0;
  virtual ~Record() {}
  virtual size_t parseFromBuffer(const u8 *buf, size_t offset, size_t maxlen) = 0;
};

class A_Record : public Record
{
public:
  sockaddr_storage value;
  Record * clone() { return new A_Record(*this); }
  ~A_Record() {}
  size_t parseFromBuffer(const u8 *buf, size_t offset, size_t maxlen);
};

class PTR_Record : public Record
{
public:
  std::string value;
  Record * clone() { return new PTR_Record(*this); }
  ~PTR_Record() {}
  size_t parseFromBuffer(const u8 *buf, size_t offset, size_t maxlen)
  {
    return Factory::parseDomainName(value, buf, offset, maxlen);
  }
};

class CNAME_Record : public Record
{
public:
  std::string value;
  Record * clone() { return new CNAME_Record(*this); }
  ~CNAME_Record() {}
  size_t parseFromBuffer(const u8 *buf, size_t offset, size_t maxlen)
  {
    return Factory::parseDomainName(value, buf, offset, maxlen);
  }
};

class Query
{
public:
  std::string name;
  u16 record_type;
  u16 record_class;

  size_t parseFromBuffer(const u8 *buf, size_t offset, size_t maxlen);
};

class Answer
{
public:
  Answer() : record(NULL) {}
  Answer(const Answer &c) : name(c.name), record_type(c.record_type),
    record_class(c.record_class), ttl(c.ttl), length(c.length),
    record(c.record->clone()) {}
  ~Answer() { delete record; }

  std::string name;
  u16 record_type;
  u16 record_class;
  u32 ttl;
  u16 length;
  Record * record;

  // Populate the object reading from buffer and returns "consumed" bytes
  size_t parseFromBuffer(const u8 *buf, size_t offset, size_t maxlen);
  Answer& operator=(const Answer &r);
};

class Packet
{
public:
  Packet() : id(0), flags(0) {}
  ~Packet() {}

  void addFlags(FLAGS fl){ flags |= fl; }
  void removeFlags(FLAGS fl){ flags &= ~fl; }
  void resetFlags() { flags = 0; }
  //size_t writeToBuffer(u8 *buf, size_t maxlen);
  size_t parseFromBuffer(const u8 *buf, size_t maxlen);

  u16 id;
  u16 flags;
  std::list<Query> queries;
  std::list<Answer> answers;
};

}

void nmap_mass_rdns(Target ** targets, int num_targets);

std::list<std::string> get_dns_servers();

#endif
