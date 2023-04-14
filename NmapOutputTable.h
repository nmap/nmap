
/***************************************************************************
 * NmapOutputTable.h -- A relatively simple class for organizing Nmap      *
 * output into an orderly table for display to the user.                   *
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

#ifndef NMAPOUTPUTTABLE_H
#define NMAPOUTPUTTABLE_H

/* Keep assert() defined for security reasons */
#undef NDEBUG
#include <assert.h>

#include "nbase.h" /* __attribute__ */

/**********************  DEFINES/ENUMS ***********************************/

/**********************  STRUCTURES  ***********************************/

/**********************  CLASSES     ***********************************/

struct NmapOutputTableCell {
  char *str;
  int strlength;
  bool weAllocated; // If we allocated str, we must free it.
  bool fullrow;
};

class NmapOutputTable {
 public:
  // Create a table of the given dimensions. Any completely
  // blank rows will be removed when printableTable() is called.
  // If the number of table rows is unknown then the highest
  // number of possible rows should be specified.
  NmapOutputTable(int nrows, int ncols);
  ~NmapOutputTable();

  // Copy specifies whether we must make a copy of item.  Otherwise we'll just save the
  // ptr (and you better not free it until this table is destroyed ).  Skip the itemlen parameter if you
  // don't know (and the function will use strlen).
  void addItem(unsigned int row, unsigned int column, bool copy, const char *item, int itemlen = -1);
  // Same as above but if fullrow is true, 'item' spans across all columns. The spanning starts from
  // the column argument (ie. 0 will be the first column)
  void addItem(unsigned int row, unsigned int column, bool fullrow, bool copy, const char *item, int itemlen = -1);

  // Like addItem except this version takes a printf-style format string followed by varargs
  void addItemFormatted(unsigned int row, unsigned int column, bool fullrow, const char *fmt, ...)
          __attribute__ ((format (printf, 5, 6))); // Offset by 1 to account for implicit "this" parameter.

  // This function sticks the entire table into a character buffer.
  // Note that the buffer is likely to be reused if you call the
  // function again, and it will also be invalidated if you free the
  // table. If size is not NULL, it will be filled with the size of
  // the ASCII table in bytes (not including the terminating NUL)
  // All blank rows will be removed from the returned string
  char *printableTable(int *size);

 private:

  bool emptyRow(unsigned int nrow);
  // The table, squished into 1D.  Access a member via getCellAddy
  struct NmapOutputTableCell *table;
  struct NmapOutputTableCell *getCellAddy(unsigned int row, unsigned int col) {
    assert(row < numRows);  assert(col < numColumns);
    return table + row * numColumns + col;
  }
  int *maxColLen; // An array that gives the maximum length of any member of each column
                  // (excluding terminator)
  // Array that tells the number of valid (> 0 length) items in each row
  int *itemsInRow;
  unsigned int numRows;
  unsigned int numColumns;
  char *tableout; // If printableTable() is called, we return this
  int tableoutsz; // Amount of space ALLOCATED for tableout.  Includes space allocated for NUL.
};


/**********************  PROTOTYPES  ***********************************/


#endif /* NMAPOUTPUTTABLE_H */

