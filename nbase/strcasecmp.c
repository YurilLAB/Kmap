
/***************************************************************************
 * strcasecmp.c -- strcasecmp and strncasecmp for systems (like Windows)   *
 * which do not already have them.                                         *
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

/* $Id$ */

#if !defined(HAVE_STRCASECMP) || !defined(HAVE_STRNCASECMP)
#include <stdlib.h>
#include <string.h>
#include "nbase.h"
#endif

#ifndef HAVE_STRCASECMP
int strcasecmp(const char *s1, const char *s2)
{
    int i, ret;
    char *cp1, *cp2;

    cp1 = safe_malloc(strlen(s1) + 1);
    cp2 = safe_malloc(strlen(s2) + 1);

    for (i = 0; i < strlen(s1) + 1; i++)
        cp1[i] = tolower((int) (unsigned char) s1[i]);
    for (i = 0; i < strlen(s2) + 1; i++)
        cp2[i] = tolower((int) (unsigned char) s2[i]);

    ret = strcmp(cp1, cp2);

    free(cp1);
    free(cp2);

    return ret;
}
#endif

#ifndef HAVE_STRNCASECMP
int strncasecmp(const char *s1, const char *s2, size_t n)
{
    int i, ret;
    char *cp1, *cp2;

    cp1 = safe_malloc(strlen(s1) + 1);
    cp2 = safe_malloc(strlen(s2) + 1);

    for (i = 0; i < strlen(s1) + 1; i++)
        cp1[i] = tolower((int) (unsigned char) s1[i]);
    for (i = 0; i < strlen(s2) + 1; i++)
        cp2[i] = tolower((int) (unsigned char) s2[i]);

    ret = strncmp(cp1, cp2, n);

    free(cp1);
    free(cp2);

    return ret;
}
#endif

