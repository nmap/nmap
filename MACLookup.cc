
/***************************************************************************
 * MACLookup.cc -- This relatively simple system handles looking up the    *
 * vendor registered to a MAC address using the nmap-mac-prefixes          *
 * database.                                                               *
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


/* Character pool memory allocation */
#include "MACLookup.h"
#include "NmapOps.h"
#include "nmap.h"
#include "nmap_error.h"
#include "charpool.h"

extern NmapOps o;

struct MAC_entry {
  int prefix; /* -1 means none set */
  char *vendor;
};

struct MAC_hash_table {
  int table_capacity; /* How many members the table can hold */
  int table_members; /* How many members it has now */
  struct MAC_entry **table;
} MacTable;

static inline int MacCharPrefix2Key(const u8 *prefix) {
  return (prefix[0] << 16) + (prefix[1] << 8) + prefix[2];
}

/* Hashes the prefix into a position from 0 to table_capacity - 1.  Does not
   check if the position is free or anything */
static inline int MACTableHash(int prefix, int table_capacity) {
  // Maybe I should think about changing this sometime.
  return prefix % table_capacity;
}

static void mac_prefix_init() {
  static int initialized = 0;
  if (initialized) return;
  initialized = 1;
  char filename[256];
  FILE *fp;
  char line[128];
  int pfx, pos;
  char *endptr, *p;
  int lineno = 0;
  struct MAC_entry *ME;

  MacTable.table_capacity = 19037;
  MacTable.table_members = 0;
  MacTable.table = (struct MAC_entry **) safe_zalloc(MacTable.table_capacity * sizeof(struct MAC_entry *));

  /* Now it is time to read in all of the entries ... */
  if (nmap_fetchfile(filename, sizeof(filename), "nmap-mac-prefixes") != 1){
    error("Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed");
    return;
  }

  fp = fopen(filename, "r");
  if (!fp) {
    error("Unable to open %s.  Ethernet vendor correlation will not be performed ", filename);
    return;
  }
  /* Record where this data file was found. */
  o.loaded_data_files["nmap-mac-prefixes"] = filename;

  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    if (*line == '#') continue;
    if (!isxdigit((int) (unsigned char) *line)) {
      error("Parse error one line #%d of %s. Giving up parsing.", lineno, filename);
      break;
    }
    /* First grab the prefix */
    pfx = strtol(line, &endptr, 16);
    if (!endptr || !isspace((int) (unsigned char) *endptr)) {
      error("Parse error one line #%d of %s. Giving up parsing.", lineno, filename);
      break;
    }
    /* Now grab the vendor */
    while(*endptr && isspace((int) (unsigned char) *endptr)) endptr++;
    assert(*endptr);
    p = endptr;
    while(*endptr && *endptr != '\n' && *endptr != '\r') endptr++;
    *endptr = '\0';

    // Create the new MAC_entry
    ME = (struct MAC_entry *) cp_alloc(sizeof(struct MAC_entry));
    ME->prefix = pfx;
    ME->vendor = cp_strdup(p);

    if (MacTable.table_members > MacTable.table_capacity * 0.8)
      error("WARNING:  nmap-mac-prefixes has grown to more than 80%% of our hash table size.  MacTable.table_capacity should be increased");

    // Now insert it into the table
    if (MacTable.table_members >= MacTable.table_capacity)
      fatal("No space for further MAC prefixes from nmap-mac-prefixes.  Increase MacTable.table_capacity");

    pos = MACTableHash(pfx, MacTable.table_capacity); 
    while (MacTable.table[pos]) pos = (pos + 1) % MacTable.table_capacity;
    MacTable.table[pos] = ME;
    MacTable.table_members++;
  }

  fclose(fp);
  return;
}


static struct MAC_entry *findMACEntry(int prefix) {
  int pos = MACTableHash(prefix, MacTable.table_capacity);

  while (MacTable.table[pos]) {
    if (MacTable.table[pos]->prefix == prefix)
      return MacTable.table[pos];
    pos = (pos + 1) % MacTable.table_capacity;
  }

  return NULL;
}

/* Takes a three byte MAC address prefix (passing the whole MAC is OK
   too) and returns the company which has registered the prefix.
   NULL is returned if no vendor is found for the given prefix or if there
   is some other error. */
const char *MACPrefix2Corp(const u8 *prefix) {
  struct MAC_entry *ent;

  if (!prefix) fatal("%s called with a NULL prefix", __func__);
  mac_prefix_init();

  ent = findMACEntry(MacCharPrefix2Key(prefix));
  return (ent)? ent->vendor : NULL;
}

/* Takes a string and looks through the table for a vendor name which
   contains that string.  Sets the first three bytes in mac_data and
   returns true for the first matching entry found.  If no entries
   match, leaves mac_data untouched and returns false.  Note that this
   is not particularly efficient and so should be rewriteen if it is
   called often */
bool MACCorp2Prefix(const char *vendorstr, u8 *mac_data) {
  if (!vendorstr) fatal("%s: vendorstr is NULL", __func__);
  if (!mac_data) fatal("%s: mac_data is NULL", __func__);
  mac_prefix_init();

  for(int i = 0; i < MacTable.table_capacity; i++ ) {
    if (MacTable.table[i])
      if (strcasestr(MacTable.table[i]->vendor, vendorstr)) {
	mac_data[0] = MacTable.table[i]->prefix >> 16;
	mac_data[1] = (MacTable.table[i]->prefix >> 8) & 0xFF;
	mac_data[2] = MacTable.table[i]->prefix & 0xFF;
	return true;
      }
  }
  return false;
}
