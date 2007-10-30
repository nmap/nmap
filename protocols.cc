
/***************************************************************************
 * protocols.cc -- Functions relating to the protocol scan and mapping     *
 * between IPproto Number <-> name.                                        *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2006 Insecure.Com LLC. Nmap is    *
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
 *   nmap-os-fingerprints or nmap-service-probes.                          *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://insecure.org/nmap/ to download Nmap.                             *
 *                                                                         *
 * We don't consider these to be added restrictions on top of the GPL, but *
 * just a clarification of how we interpret "derived works" as it applies  *
 * to our GPL-licensed Nmap product.  This is similar to the way Linus     *
 * Torvalds has announced his interpretation of how "derived works"        *
 * applies to Linux kernel modules.  Our interpretation refers only to     *
 * Nmap - we don't speak for any other GPL products.                       *
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
 * listed in the included Copying.OpenSSL file, and distribute linked      *
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
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one the            *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License for more details at                              *
 * http://www.gnu.org/copyleft/gpl.html , or in the COPYING file included  *
 * with Nmap.                                                              *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "protocols.h"
#include "NmapOps.h"
#include "services.h"
#include "charpool.h"
#include "nmap_error.h"
#include "utils.h"

extern NmapOps o;
static int numipprots = 0;
static struct protocol_list *protocol_table[PROTOCOL_TABLE_SIZE];
static int protocols_initialized = 0;

static int nmap_protocols_init() {
  if (protocols_initialized) return 0;

  char filename[512];
  FILE *fp;
  char protocolname[128];
  unsigned short protno;
  char *p;
  char line[1024];
  int lineno = 0;
  struct protocol_list *current, *previous;
  int res;

  if (nmap_fetchfile(filename, sizeof(filename), "nmap-protocols") != 1) {
    error("Unable to find nmap-protocols!  Resorting to /etc/protocols");
    strcpy(filename, "/etc/protocols");
  }

  fp = fopen(filename, "r");
  if (!fp) {
    fatal("Unable to open %s for reading protocol information", filename);
  }
  /* Record where this data file was found. */
  o.loaded_data_files["nmap-protocols"] = filename;

  memset(protocol_table, 0, sizeof(protocol_table));
  
  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    p = line;
    while(*p && isspace((int) *p))
      p++;
    if (*p == '#')
      continue;
    res = sscanf(line, "%127s %hu", protocolname, &protno);
    if (res !=2)
      continue;
    protno = htons(protno);

    /* Now we make sure our protocols don't have duplicates */
    for(current = protocol_table[0], previous = NULL;
	current; current = current->next) {
      if (protno == current->protoent->p_proto) {
	if (o.debugging) {
	  error("Protocol %d is duplicated in protocols file %s", ntohs(protno), filename);
	}
	break;
      }
      previous = current;
    }
    if (current)
      continue;

    numipprots++;

    current = (struct protocol_list *) cp_alloc(sizeof(struct protocol_list));
    current->protoent = (struct protoent *) cp_alloc(sizeof(struct protoent));
    current->next = NULL;
    if (previous == NULL) {
      protocol_table[protno] = current;
    } else {
      previous->next = current;
    }
    current->protoent->p_name = cp_strdup(protocolname);
    current->protoent->p_proto = protno;
    current->protoent->p_aliases = NULL;
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
  struct protocol_list *current;
  int bucket, t=0;

  if (!protocols_initialized && nmap_protocols_init() == -1)
    fatal("%s: Couldn't get protocol numbers", __func__);

  for(bucket = 0; bucket < PROTOCOL_TABLE_SIZE; bucket++) {
    for(current = protocol_table[bucket % PROTOCOL_TABLE_SIZE]; current; current = current->next) {
      if (wildtest(mask, current->protoent->p_name)) {
        porttbl[ntohs(current->protoent->p_proto)] |= SCAN_PROTOCOLS;
        t++;
      }
    }
  }

  return t;

}


struct protoent *nmap_getprotbynum(int num) {
  struct protocol_list *current;

  if (nmap_protocols_init() == -1)
    return NULL;

  for(current = protocol_table[num % PROTOCOL_TABLE_SIZE];
      current; current = current->next) {
    if (num == current->protoent->p_proto)
      return current->protoent;
  }

  /* Couldn't find it ... oh well. */
  return NULL;
}
