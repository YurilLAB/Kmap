
/***************************************************************************
 * kmap_error.cc -- Some simple error handling routines.                   *
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

#include "kmap_error.h"
#include "output.h"
#include "KmapOps.h"
#include "xml.h"

#include <errno.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

extern KmapOps o;

#ifdef WIN32
#include <windows.h>
#endif /* WIN32 */


#ifndef HAVE_STRERROR
char *strerror(int errnum) {
  static char buf[1024];
  sprintf(buf, "your system is too old for strerror of errno %d\n", errnum);
  return buf;
}
#endif

void fatal(const char *fmt, ...) {
  time_t timep;
  struct timeval tv;
  va_list  ap;

  gettimeofday(&tv, NULL);
  timep = time(NULL);

  va_start(ap, fmt);
  log_vwrite(LOG_NORMAL|LOG_STDERR, fmt, ap);
  va_end(ap);
  log_write(LOG_NORMAL|LOG_STDERR, "\nQUITTING!\n");

  if (xml_tag_open())
    xml_close_start_tag();
  if (!xml_root_written())
    xml_start_tag("kmaprun");
  /* Close all open XML elements but one. */
  while (xml_depth() > 1) {
    xml_end_tag();
    xml_newline();
  }
  if (xml_depth() == 1) {
    char errbuf[1024];

    va_start(ap, fmt);
    Vsnprintf(errbuf, sizeof(errbuf), fmt, ap);
    va_end(ap);

    xml_start_tag("runstats");
    print_xml_finished_open(timep, &tv);
    xml_attribute("exit", "error");
    xml_attribute("errormsg", "%s", errbuf);
    xml_close_empty_tag();

    print_xml_hosts();
    xml_newline();

    xml_end_tag(); /* runstats */
    xml_newline();

    xml_end_tag(); /* kmaprun */
    xml_newline();
  }

  exit(1);
}

void error(const char *fmt, ...) {
  va_list  ap;

  va_start(ap, fmt);
  log_vwrite(LOG_NORMAL|LOG_STDERR, fmt, ap);
  va_end(ap);
  log_write(LOG_NORMAL|LOG_STDERR , "\n");
  return;
}

void pfatal(const char *fmt, ...) {
  time_t timep;
  struct timeval tv;
  va_list ap;
  int error_number;
  char errbuf[1024], *strerror_s;

#ifdef WIN32
  error_number = GetLastError();
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
                NULL, error_number, MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR) &strerror_s,  0, NULL);
#else
  error_number = errno;
  strerror_s = strerror(error_number);
#endif

  gettimeofday(&tv, NULL);
  timep = time(NULL);

  va_start(ap, fmt);
  Vsnprintf(errbuf, sizeof(errbuf), fmt, ap);
  va_end(ap);

  log_write(LOG_NORMAL|LOG_STDERR, "%s: %s (%d)\n",
            errbuf, strerror_s, error_number);

  if (xml_tag_open())
    xml_close_start_tag();
  if (!xml_root_written())
    xml_start_tag("kmaprun");
  /* Close all open XML elements but one. */
  while (xml_depth() > 1) {
    xml_end_tag();
    xml_newline();
  }
  if (xml_depth() == 1) {
    xml_start_tag("runstats");
    print_xml_finished_open(timep, &tv);
    xml_attribute("exit", "error");
    xml_attribute("errormsg", "%s: %s (%d)", errbuf, strerror_s, error_number);
    xml_close_empty_tag();

    print_xml_hosts();
    xml_newline();

    xml_end_tag(); /* runstats */
    xml_newline();

    xml_end_tag(); /* kmaprun */
    xml_newline();
  }

#ifdef WIN32
  HeapFree(GetProcessHeap(), 0, strerror_s);
#endif

  log_flush(LOG_NORMAL);
  fflush(stderr);
  exit(1);
}

/* This function is the Kmap version of perror. It is like pfatal, but it
   doesn't write to XML and it only returns, doesn't exit. */
void gh_perror(const char *fmt, ...) {
  va_list ap;
  int error_number;
  char *strerror_s;

#ifdef WIN32
  error_number = GetLastError();
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
                NULL, error_number, MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR) &strerror_s,  0, NULL);
#else
  error_number = errno;
  strerror_s = strerror(error_number);
#endif

  va_start(ap, fmt);
  log_vwrite(LOG_NORMAL|LOG_STDERR, fmt, ap);
  va_end(ap);
  log_write(LOG_NORMAL|LOG_STDERR, ": %s (%d)\n",
    strerror_s, error_number);

#ifdef WIN32
  HeapFree(GetProcessHeap(), 0, strerror_s);
#endif

  log_flush(LOG_NORMAL);
  fflush(stderr);
  return;
}
