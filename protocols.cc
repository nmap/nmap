
/***************************************************************************
 * protocols.cc -- Functions relating to the protocol scan and mapping     *
 * between IPproto Number <-> name.                                        *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2020 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 *                                                                         *
 * This program is distributed under the terms of the Nmap Public Source   *
 * License (NPSL). The exact license text applying to a particular Nmap    *
 * release or source code control revision is contained in the LICENSE     *
 * file distributed with that version of Nmap or source code control       *
 * revision. More Nmap copyright/legal information is available from       *
 * https://nmap.org/book/man-legal.html, and further information on the    *
 * NPSL license itself can be found at https://nmap.org/npsl. This header  *
 * summarizes some key points from the Nmap license, but is no substitute  *
 * for the actual license text.                                            *
 *                                                                         *
 * Nmap is generally free for end users to download and use themselves,    *
 * including commercial use. It is available from https://nmap.org.        *
 *                                                                         *
 * The Nmap license generally prohibits companies from using and           *
 * redistributing Nmap in commercial products, but we sell a special Nmap  *
 * OEM Edition with a more permissive license and special features for     *
 * this purpose. See https://nmap.org/oem                                  *
 *                                                                         *
 * If you have received a written Nmap license agreement or contract       *
 * stating terms other than these (such as an Nmap OEM license), you may   *
 * choose to use and redistribute Nmap under those terms instead.          *
 *                                                                         *
 * The official Nmap Windows builds include the Npcap software             *
 * (https://npcap.org) for packet capture and transmission. It is under    *
 * separate license terms which forbid redistribution without special      *
 * permission. So the official Nmap Windows builds may not be              *
 * redistributed without special permission (such as an Nmap OEM           *
 * license).                                                               *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to submit your         *
 * changes as a Github PR or by email to the dev@nmap.org mailing list     *
 * for possible incorporation into the main distribution. Unless you       *
 * specify otherwise, it is understood that you are offering us very       *
 * broad rights to use your submissions as described in the Nmap Public    *
 * Source License Contributor Agreement. This is important because we      *
 * fund the project by selling licenses with various terms, and also       *
 * because the inability to relicense code has caused devastating          *
 * problems for other Free Software projects (such as KDE and NASM).       *
 *                                                                         *
 * The free version of Nmap is distributed in the hope that it will be     *
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of  *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,        *
 * indemnification and commercial support are all available through the    *
 * Npcap OEM program--see https://nmap.org/oem.                            *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "protocols.h"
#include "NmapOps.h"
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
    while(*p && isspace((int) (unsigned char) *p))
      p++;
    if (*p == '#')
      continue;
    res = sscanf(line, "%127s %hu", protocolname, &protno);
    if (res !=2)
      continue;

    /* Now we make sure our protocols don't have duplicates */
    for(current = protocol_table[protno % PROTOCOL_TABLE_SIZE], previous = NULL;
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
      protocol_table[protno % PROTOCOL_TABLE_SIZE] = current;
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
