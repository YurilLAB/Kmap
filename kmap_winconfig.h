
/***************************************************************************
 * kmap_winconfig.h -- Since the Windows port is currently eschewing       *
 * autoconf-style configure scripts, kmap_winconfig.h contains the         *
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

#ifndef KMAP_WINCONFIG_H
#define KMAP_WINCONFIG_H
/* Without this, Windows will give us all sorts of crap about using functions
   like strcpy() even if they are done safely */
#define _CRT_SECURE_NO_DEPRECATE 1
#define KMAP_PLATFORM "i686-pc-windows-windows"

/* Suppress windows.h's min/max function-like macros so that std::min and
 * std::max in C++ code compile correctly. Without NOMINMAX, windef.h
 * defines min(a,b) and max(a,b) as preprocessor macros, which then expand
 * std::min(...) into std::((...) ? ... : ...) — illegal C++ that surfaces
 * as MSVC errors C2589 ("'(': illegal token on right side of '::'") and
 * C2062 ("type 'unknown-type' unexpected") at every std::min/std::max
 * call site. Defining NOMINMAX before any windows.h chain keeps the
 * standard C++ template versions usable everywhere. */
#ifndef NOMINMAX
#define NOMINMAX 1
#endif

#define HAVE_OPENSSL 1
#define HAVE_LIBSSH2 1
#define HAVE_LIBZ 1
/* Since MSVC 2010, stdint.h is included as part of C99 compatibility */
#define HAVE_STDINT_H 1

#define LUA_INCLUDED 1
#undef PCAP_INCLUDED
#define DNET_INCLUDED 1
#define PCRE_INCLUDED 1
#define LIBSSH2_INCLUDED 1
#define ZLIB_INCLUDED 1

/* Pre-include the C++ standard stream headers here, before any nbase
 * header gets a chance to run.
 *
 * Why: nbase_winunix.h does `#define close(x) closesocket(x)` so that
 * upstream nmap socket code stays portable. That macro is harmless for
 * socket I/O, but it leaks into any C++ standard header included AFTER
 * it that has a member function named close() — most visibly
 * <fstream>'s basic_filebuf::close, which appears at MSVC fstream
 * line ~1166 as `void close()`. The preprocessor sees `close()` and
 * tries to expand the close(x) macro with zero arguments, producing
 * warning C4003 ("not enough arguments for function-like macro
 * invocation 'close'") at every translation unit that transitively
 * pulls in <fstream> through, e.g., <sstream> via std::ostringstream.
 *
 * Pre-including the stream headers here parses them once with the real
 * ::close (or none at all) before nbase_winunix.h's macro is later
 * defined. Subsequent #include <fstream>/<sstream>/<iostream> are
 * no-ops thanks to standard include guards. C++-only; wrap so the
 * file is still safe if pulled into C compilation. */
#ifdef __cplusplus
#include <fstream>
#include <sstream>
#include <iostream>
#endif

#endif /* KMAP_WINCONFIG_H */

