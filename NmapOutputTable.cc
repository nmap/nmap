
/***************************************************************************
 * NmapOutputTable.cc -- A relatively simple class for organizing Nmap     *
 * output into an orderly table for display to the user.                   *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
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

/* $Id$ */

#ifdef WIN32
#include "nmap_winconfig.h"
#endif

#include "NmapOutputTable.h"
#include "nmap_error.h"

#include <stdlib.h>

NmapOutputTable::NmapOutputTable(int nrows, int ncols) {
  numRows = nrows;
  numColumns = ncols;
  assert(numRows > 0);
  assert(numColumns > 0);
  table = (struct NmapOutputTableCell *) safe_zalloc(sizeof(struct NmapOutputTableCell) * nrows * ncols);
  maxColLen = (int *) safe_zalloc(sizeof(*maxColLen) * ncols);
  itemsInRow = (int *) safe_zalloc(sizeof(*itemsInRow) * nrows);
  tableout = NULL;
  tableoutsz = 0;
}

NmapOutputTable::~NmapOutputTable() {
  unsigned int col, row;
  struct NmapOutputTableCell *cell;

  for(row = 0; row < numRows; row++) {
    for(col = 0; col < numColumns; col++) {
      cell = getCellAddy(row, col);
      if (cell->weAllocated) {
        assert(cell->str);
        free(cell->str);
      }
    }
  }

  free(table);
  free(maxColLen);
  free(itemsInRow);
  if (tableout) free(tableout);
}

void NmapOutputTable::addItem(unsigned int row, unsigned int column, bool fullrow,
                                bool copy, const char *item, int itemlen) {
  struct NmapOutputTableCell *cell;
  int mc = maxColLen[column];

  addItem(row, column, copy, item, itemlen);

  if(fullrow) {
    maxColLen[column] = mc;
    cell = getCellAddy(row, column);
    cell->fullrow = fullrow;
  }
  return;
}

void NmapOutputTable::addItem(unsigned int row, unsigned int column, bool copy, const char *item,
                              int itemlen) {
  struct NmapOutputTableCell *cell;

  assert(row < numRows);
  assert(column < numColumns);

  if (itemlen < 0)
    itemlen = strlen(item);

  if (itemlen == 0)
    return;

  cell = getCellAddy(row, column);
  assert(cell->str == NULL); // I'll worry about replacing members if I ever need it
  itemsInRow[row]++;

  cell->strlength = itemlen;

  if (copy) {
    cell->str = (char *) safe_malloc(itemlen + 1);
    memcpy(cell->str, item, itemlen);
    cell->str[itemlen] = '\0';
  } else {
    cell->str = (char *) item;
  }
  cell->weAllocated = copy;

  if (maxColLen[column] < itemlen)
    maxColLen[column] = itemlen;

  return;
}

void NmapOutputTable::addItemFormatted(unsigned int row,
                                          unsigned int column,
                                          bool fullrow,
                                          const char *fmt, ...) {
  struct NmapOutputTableCell *cell;
  int mc = maxColLen[column];
  unsigned int res;
  va_list ap;
  va_start(ap,fmt);
  char buf[4096];
  res = Vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (res > sizeof(buf))
    fatal("NmapOutputTable only supports adding up to 4096 to a cell via %s.", __func__);

  addItem(row, column, fullrow, true, buf, res);

  if(fullrow) {
    maxColLen[column] = mc;
    cell = getCellAddy(row, column);
    cell->fullrow = fullrow;
  }
}

/* True if every column in nrow is empty */
bool NmapOutputTable::emptyRow(unsigned int nrow) {
        NmapOutputTableCell *cell;
        unsigned int col;
        bool isEmpty = true;

        assert(nrow < numRows);

        for(col = 0 ; col < numColumns; col++) {
                cell = getCellAddy(nrow, col);
                if(cell->strlength > 0) {
                        isEmpty = false;
                        break;
                }
        }
        return isEmpty;
}

 // This function sticks the entire table into a character buffer.
 // Note that the buffer is likely to be reused if you call the
 // function again, and it will also be invalidated if you free the
 // table. If size is not NULL, it will be filled with the size of
 // the ASCII table in bytes (not including the terminating NUL)
 // All blank rows are removed from the returned string
char *NmapOutputTable::printableTable(int *size) {
  unsigned int col, row;
  int p = 0; /* The offset into tableout */
  int clen = 0;
  int i;
  struct NmapOutputTableCell *cell;
  int validthisrow;

  if (tableoutsz == 0) {
    tableoutsz = 512; /* Start us off with half a k */
    tableout = (char *) safe_malloc(tableoutsz);
  }

  for(row = 0; row < numRows; row++) {
    validthisrow = 0;

    if(emptyRow(row))
        continue;

    cell = getCellAddy(row, 0);
    if(cell->fullrow && cell->strlength > 0) {
      /* Full rows are easy, just make sure we have the space + \n\0 */
      if (cell->strlength + p + 2 > tableoutsz) {
        tableoutsz = (cell->strlength + p + 2) * 2;
        tableout = (char *) safe_realloc(tableout, tableoutsz);
      }
      memcpy(tableout + p, cell->str,  cell->strlength);
      p += cell->strlength;
    } else {
      for(col = 0; col < numColumns; col++) {
        cell = getCellAddy(row, col);
        clen = maxColLen[col];
        /* Cells get padded with an extra space + \n\0 */
        if (clen + p + 3 > tableoutsz) {
          tableoutsz = (cell->strlength + p + 2) * 2;
          tableout = (char *) safe_realloc(tableout, tableoutsz);
        }
        if (cell->strlength > 0) {
          memcpy(tableout + p, cell->str,  cell->strlength);
          p += cell->strlength;
          validthisrow++;
        }
        // No point leaving trailing spaces ...
        if (validthisrow < itemsInRow[row]) {
          for(i=cell->strlength; i <= clen; i++) // one extra because of space between columns
            *(tableout + p++) = ' ';
        }
      }
    }
    *(tableout + p++) = '\n';
  }
  *(tableout + p) = '\0';

  if (size) *size = p;
  return tableout;
}
