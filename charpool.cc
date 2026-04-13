
/***************************************************************************
 * charpool.cc -- Handles Kmap's "character pool" memory allocation        *
 * system.                                                                 *
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

#include <stddef.h>
#undef NDEBUG
#include <assert.h>
#include <climits>

#include "nbase.h"

/* Character pool memory allocation */
#include "charpool.h"
#include "kmap_error.h"

static CharPool g_charpool (16384);

const char *cp_strndup(const char *src, int len) {
  return g_charpool.dup(src, len);
}
const char *cp_strdup(const char *src) {
  return g_charpool.dup(src);
}
void cp_free(void) {
  return g_charpool.clear();
}

class StrTable {
  public:
  StrTable() {
    memset(table, 0, sizeof(table));
    for (int i = 1; i <= CHAR_MAX; i++) {
      table[i*2] = static_cast<char>(i);
    }
  }
  const char *get(char c) { assert(c >= 0); return &table[c*2]; }
  private:
  char table[2*(CHAR_MAX + 1)];
};
static StrTable g_table;

const char *cp_char2str(char c) {
  return g_table.get(c);
}

CharPool::CharPool(size_t init_sz) {
  assert(init_sz >= 256);
  /* Create our char pool */
  currentbucketsz = init_sz;
  nexti = 0;
  char *b = (char *) safe_malloc(currentbucketsz);
  buckets.push_back(b);
}

void CharPool::clear(void) {
  for (BucketList::iterator it=buckets.begin(); it != buckets.end(); it++) {
    free(*it);
  }
  buckets.clear();
}

const char *CharPool::dup(const char *src, int len) {
  if (len < 0)
    len = strlen(src);
  if (len == 0)
    return g_table.get('\0');
  else if (len == 1)
    return g_table.get(*src);

  int sz = len + 1;
  char *p = buckets.back() + nexti;

  while (nexti + sz > currentbucketsz) {
    /* Doh!  We've got to make room */
    currentbucketsz <<= 1;
    nexti = 0;
    p = (char *) safe_malloc(currentbucketsz);
    buckets.push_back(p);
  }

  nexti += sz;
  p[len] = '\0';
  return (const char *) memcpy(p, src, len);
}
