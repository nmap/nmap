
/***************************************************************************
 * protocols.cc -- Functions relating to the protocol scan and mapping     *
 * between IPproto Number <-> name.                                        *
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

#include "protocols.h"
#include "NmapOps.h"
#include "string_pool.h"
#include "nmap_error.h"
#include "utils.h"

#include <map>

extern NmapOps o;

struct strcmp_comparator {
  bool operator()(const char *a, const char *b) const {
    return strcmp(a, b) < 0;
  }
};

// IP Protocol number is 8 bits wide
// protocol_table[IPPROTO_TCP] == {"tcp", 6}
static struct nprotoent *protocol_table[UCHAR_MAX];
// proto_map["tcp"] = {"tcp", 6}
typedef std::map<const char *, struct nprotoent, strcmp_comparator> ProtoMap;
static ProtoMap proto_map;

static int nmap_protocols_init() {
  static int protocols_initialized = 0;
  if (protocols_initialized) return 0;

  char filename[512];
  FILE *fp;
  char protocolname[128];
  unsigned short protno;
  char *p;
  char line[1024];
  int lineno = 0;
  int res;

  if (nmap_fetchfile(filename, sizeof(filename), "nmap-protocols") != 1) {
    error("Unable to find nmap-protocols!  Resorting to /etc/protocols");
    strcpy(filename, "/etc/protocols");
  }

  fp = fopen(filename, "r");
  if (!fp) {
    pfatal("Unable to open %s for reading protocol information", filename);
  }
  /* Record where this data file was found. */
  o.loaded_data_files["nmap-protocols"] = filename;

  memset(protocol_table, 0, sizeof(protocol_table));

  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    p = line;
    while(*p && isspace((int) (unsigned char) *p))
      p++;
    if (*p == '#' || *p == '\0')
      continue;
    res = sscanf(line, "%127s %hu", protocolname, &protno);
    if (res !=2 || protno > UCHAR_MAX) {
      error("Parse error in protocols file %s line %d", filename, lineno);
      continue;
    }

    struct nprotoent ent;
    // Using string_pool means we don't have to copy this data; the pointer is unique!
    ent.p_name = string_pool_insert(protocolname);
    ent.p_proto = protno;
    std::pair<ProtoMap::iterator, bool> status = proto_map.insert(std::pair<const char *, struct nprotoent>(ent.p_name, ent));

    /* Now we make sure our protocols don't have duplicates */
    if (!status.second) {
      if (o.debugging > 1) {
        error("Protocol %hu (%s) has duplicate number (%hu) in protocols file %s", status.first->second.p_proto, ent.p_name, protno, filename);
      }
      continue;
    }

    if (protocol_table[protno]) {
      if (o.debugging > 1) {
        error("Protocol %hu (%s) has duplicate name (%s) in protocols file %s", protno, protocol_table[protno]->p_name, ent.p_name, filename);
      }
      continue;
    }

    protocol_table[protno] = &status.first->second;
  }
  fclose(fp);
  protocols_initialized = 1;
  return 0;
}


/* Adds protocols whose names match mask to porttbl.
 * Increases the prot_count in ports by the number of protocols added.
 * Returns the number of protocols added.
 */


int addprotocolsfromservmask(char *mask, u8 *porttbl) {
  ProtoMap::const_iterator it;
  int t=0;

  if (nmap_protocols_init() != 0)
    fatal("%s: Couldn't get protocol numbers", __func__);

  // Check for easy ones: plain string match.
  it = proto_map.find(mask);
  if (it != proto_map.end()) {
    // Matched! No need to try wildtest on everything.
    porttbl[it->second.p_proto] |= SCAN_PROTOCOLS;
    return 1;
  }
  // No match? iterate and use wildtest.
  for(it = proto_map.begin(); it != proto_map.end(); it++) {
    if (wildtest(mask, it->second.p_name)) {
      porttbl[it->second.p_proto] |= SCAN_PROTOCOLS;
      t++;
    }
  }

  return t;

}


const struct nprotoent *nmap_getprotbynum(int num) {

  if (nmap_protocols_init() == -1)
    return NULL;

  assert(num >= 0 && num < UCHAR_MAX);
  return protocol_table[num];
}

const struct nprotoent *nmap_getprotbyname(const char *name) {

  if (nmap_protocols_init() == -1)
    return NULL;

  ProtoMap::const_iterator it = proto_map.find(name);
  if (it != proto_map.end()) {
    return &it->second;
  }
  return NULL;
}
