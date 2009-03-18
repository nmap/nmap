
/***************************************************************************
 * NmapOutputTable.cc -- A relatively simple class for organizing Nmap     *
 * output into an orderly table for display to the user.                   *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2008 Insecure.Com LLC. Nmap is    *
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
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://nmap.org to download Nmap.                                       *
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
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one of the         *
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
 * General Public License v2.0 for more details at                         *
 * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
 * included with Nmap.                                                     *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#ifdef WIN32
#include "nmap_winconfig.h"
#endif

#include "NmapOutputTable.h"
#include "utils.h"

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

// Returns the maximum size neccessary to create a printableTable() (the 
// actual size could be less);
int NmapOutputTable::printableSize() {

  struct NmapOutputTableCell *cell;
  int rowlen = 0;
  unsigned int i;

  for(i = 0; i < numColumns; i++) {
    rowlen += maxColLen[i]; 
  }

  /* Add the delimeter between each column, and the final newline */
  rowlen += numColumns;

  // if one of the fullrow tables is larger than the single column
  // roles then the maximal rowlen needs to be adjusted.
  for(i = 0; i < numRows; i++) {
    cell = getCellAddy(i, 0);
    if(cell->fullrow && cell->strlength + 1 > rowlen)
      rowlen = cell->strlength + 1;  /* Account for the newline with the +1 */
  }
  
  return rowlen * numRows;

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
  int maxsz = printableSize();
  char *p;
  int clen = 0;
  int i;
  struct NmapOutputTableCell *cell;
  int validthisrow;

  if (maxsz >= tableoutsz) {
    tableoutsz = maxsz + 1;
    tableout = (char *) safe_realloc(tableout, tableoutsz);
  }
  p = tableout;

  for(row = 0; row < numRows; row++) {
    validthisrow = 0;

    if(emptyRow(row)) 
	continue;

    cell = getCellAddy(row, 0);
    if(cell->fullrow && cell->strlength > 0) {
      memcpy(p, cell->str,  cell->strlength);
      p += cell->strlength;
    } else {
      for(col = 0; col < numColumns; col++) {
        cell = getCellAddy(row, col);
        clen = maxColLen[col];
        if (cell->strlength > 0) {
          memcpy(p, cell->str,  cell->strlength);
          p += cell->strlength;
          validthisrow++;
        }
        // No point leaving trailing spaces ...
        if (validthisrow < itemsInRow[row]) {
          for(i=cell->strlength; i <= clen; i++) // one extra because of space between columns
            *(p++) = ' ';
        }
      }
    }
    *(p++) = '\n';
  }
  *p = '\0';
  if (size) *size = p - tableout;
  return tableout;
}
