/***************************************************************************
 * nmap_dns.h -- Handles parallel reverse DNS resolution for target IPs    *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2015 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
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
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
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
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
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

#ifndef NMAP_DNS_H
#define NMAP_DNS_H

class Target;

#include "nbase/nbase.h"

#include <string>
#include <list>

#include <algorithm>
#include <sstream>


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

const std::string IPV4_PTR_DOMAIN = ".in-addr.arpa";
const std::string IPV6_PTR_DOMAIN = ".ip6.arpa";

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
  size_t writeToBuffer(u8 *buf, size_t maxlen);
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
