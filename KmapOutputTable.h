
/***************************************************************************
 * KmapOutputTable.h -- A relatively simple class for organizing Kmap      *
 * output into an orderly table for display to the user.                   *
 *                                                                         *
 ***********************IMPORTANT KMAP LICENSE TERMS************************
 *
 * The Kmap Security Scanner is (C) 1996-2026 Kmap Software LLC ("The Kmap
 * Project"). Kmap is also a registered trademark of the Kmap Project.
 *
 * This program is distributed under the terms of the Kmap Public Source
 * License (NPSL). The exact license text applying to a particular Kmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Kmap or source code control
 * revision. More Kmap copyright/legal information is available from
 * https://github.com/YurilLAB/Kmap/blob/master/LICENSE, and further information on the
 * NPSL license itself can be found at https://github.com/YurilLAB/Kmap/blob/master/LICENSE . This
 * header summarizes some key points from the Kmap license, but is no
 * substitute for the actual license text.
 *
 * Kmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://github.com/YurilLAB/Kmap.
 *
 * The Kmap license generally prohibits companies from using and
 * redistributing Kmap in commercial products, but we sell a special Kmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://github.com/YurilLAB/Kmap
 *
 * If you have received a written Kmap license agreement or contract
 * stating terms other than these (such as an Kmap OEM license), you may
 * choose to use and redistribute Kmap under those terms instead.
 *
 * The official Kmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Kmap Windows builds may not be redistributed
 * without special permission (such as an Kmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Kmap to new platforms, fix bugs, and
 * add new features. You are highly encouraged to submit your changes as a
 * Github PR at https://github.com/YurilLAB/Kmap for possible incorporation
 * into the main distribution. Unless you specify otherwise, it
 * is understood that you are offering us very broad rights to use your
 * submissions as described in the Kmap Public Source License Contributor
 * Agreement. This is important because we fund the project by selling licenses
 * with various terms, and also because the inability to relicense code has
 * caused devastating problems for other Free Software projects (such as KDE
 * and NASM).
 *
 * The free version of Kmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Kmap project -- see https://github.com/YurilLAB/Kmap
 *
 ***************************************************************************/

/* $Id$ */

#ifndef KMAPOUTPUTTABLE_H
#define KMAPOUTPUTTABLE_H

/* Keep assert() defined for security reasons */
#undef NDEBUG
#include <assert.h>

#include "nbase.h" /* __attribute__ */

/**********************  DEFINES/ENUMS ***********************************/

/**********************  STRUCTURES  ***********************************/

/**********************  CLASSES     ***********************************/

struct KmapOutputTableCell {
  char *str;
  int strlength;
  bool weAllocated; // If we allocated str, we must free it.
  bool fullrow;
};

class KmapOutputTable {
 public:
  // Create a table of the given dimensions. Any completely
  // blank rows will be removed when printableTable() is called.
  // If the number of table rows is unknown then the highest
  // number of possible rows should be specified.
  KmapOutputTable(int nrows, int ncols);
  ~KmapOutputTable();

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
  struct KmapOutputTableCell *table;
  struct KmapOutputTableCell *getCellAddy(unsigned int row, unsigned int col) {
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


#endif /* KMAPOUTPUTTABLE_H */

