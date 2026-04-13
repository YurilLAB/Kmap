
/***************************************************************************
 * utils.cc -- Miscellaneous utils that didn't fit into any of the other   *
 * source files.                                                           *
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
 * https://kmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://kmap.org/npsl/ . This
 * header summarizes some key points from the Kmap license, but is no
 * substitute for the actual license text.
 *
 * Kmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://kmap.org.
 *
 * The Kmap license generally prohibits companies from using and
 * redistributing Kmap in commercial products, but we sell a special Kmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://kmap.org/oem/
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
 * Github PR or by email to the dev@kmap.org mailing list for possible
 * incorporation into the main distribution. Unless you specify otherwise, it
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
 * Npcap OEM program--see https://kmap.org/oem/
 *
 ***************************************************************************/

#ifndef UTILS_H
#define UTILS_H 1

#include "common.h"

#include <stdlib.h>

#include <stdarg.h>
#include <stdio.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "global_structures.h"

/* Function prototypes */
bool contains(const char *source, const char *substring);
bool meansRandom(const char *source);
bool isNumber_u8(const char *source, int base = 10);
bool isNumber_u16(const char *source, int base = 10);
bool isNumber_u32(const char *source, int base = 10);
u8 *parseBufferSpec(char *str, size_t *outlen);
int bitcmp(u8 *a, u8*b, int len);
int removechar(char *string, char c);
int removecolon(char *string);
void luis_hdump(char *cp, unsigned int length);
int validate_number_spec(const char *str);
int parse_u8(const char *str, u8 *dstbuff);
int parse_u16(const char *str, u16 *dstbuff);
int parse_u32(const char *str, u32 *dstbuff);
int print_hexdump(int level, const u8 *cp, u32 length);

#endif /* UTILS_H */











