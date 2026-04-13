
/***************************************************************************
 * nping_winconfig.h -- Since the Windows port is currently eschewing      *
 * autoconf-style configure scripts, nping_winconfig.h contains the        *
 * platform-specific definitions for Windows and is used as a replacement  *
 * for config.h                                                            *
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

/* $Id: kmap_winconfig.h 12955 2009-04-15 00:37:03Z fyodor $ */

#ifndef NPING_WINCONFIG_H
#define NPING_WINCONFIG_H
/* Without this, Windows will give us all sorts of crap about using functions
   like strcpy() even if they are done safely */
#define _CRT_SECURE_NO_DEPRECATE 1

//#ifndef NPING_NAME
//	#define NPING_NAME "Kmap"
//	#define NPING_URL "https://kmap.org"
//#endif

#ifdef NPING_PLATFORM
	#undef NPING_PLATFORM 
#endif

#define NPING_PLATFORM "i686-pc-windows-windows"

#define HAVE_OPENSSL 1
/* Apparently __func__ isn't yet supported */
#define __func__ __FUNCTION__
typedef unsigned __int32 u_int32_t;
typedef unsigned __int16 u_int16_t;
typedef unsigned __int8 u_int8_t;

#endif /* NPING_WINCONFIG_H */
