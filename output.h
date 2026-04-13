
/***************************************************************************
 * output.h -- Handles the Kmap output system.  This currently involves    *
 * console-style human readable output, XML output, Script |<iddi3         *
 * output, and the legacy grepable output (used to be called "machine      *
 * readable").  I expect that future output forms (such as HTML) may be    *
 * created by a different program, library, or script using the XML        *
 * output.                                                                 *
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

#ifndef OUTPUT_H
#define OUTPUT_H

#include <nbase.h> // __attribute__

#define LOG_NUM_FILES 5 /* # of values that actual files (they must come first */
#define LOG_FILE_MASK 31 /* The mask for log types in the file array */
#define LOG_NORMAL 1
#define LOG_MACHINE 2
#define LOG_SKID 4
#define LOG_XML 8
#define LOG_JSON 16
#define LOG_STDOUT 1024
#define LOG_STDERR 2048
#define LOG_SKID_NOXLT 4096
#define LOG_MAX LOG_SKID_NOXLT /* The maximum log type value */

#define LOG_PLAIN LOG_NORMAL|LOG_SKID|LOG_STDOUT

#define LOG_NAMES {"normal", "machine", "$Cr!pT |<!dd!3", "XML", "JSON"}

#define PCAP_OPEN_ERRMSG "Call to pcap_open_live() failed three times. "\
"There are several possible reasons for this, depending on your operating "\
"system:\nLINUX: If you are getting Socket type not supported, try "\
"modprobe af_packet or recompile your kernel with PACKET enabled.\n "\
 "*BSD:  If you are getting device not configured, you need to recompile "\
 "your kernel with Berkeley Packet Filter support.  If you are getting "\
 "No such file or directory, try creating the device (eg cd /dev; "\
 "MAKEDEV <device>; or use mknod).\n*WINDOWS:  Kmap only supports "\
 "ethernet interfaces on Windows for most operations because Microsoft "\
 "disabled raw sockets as of Windows XP SP2.  Depending on the reason for "\
 "this error, it is possible that the --unprivileged command-line argument "\
 "will help.\nSOLARIS:  If you are trying to scan localhost or the "\
 "address of an interface and are getting '/dev/lo0: No such file or "\
 "directory' or 'lo0: No DLPI device found', complain to Sun.  I don't "\
 "think Solaris can support advanced localhost scans.  You can probably "\
 "use \"-Pn -sT localhost\" though.\n\n"

#include "scan_lists.h"
#ifndef NOLUA
#include "nse_main.h"
#endif
class PortList;
class Target;

#include <stdarg.h>
#include <string>

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

/* Prints the familiar Kmap tabular output showing the "interesting"
   ports found on the machine.  It also handles the Machine/Grepable
   output and the XML output.  It is pretty ugly -- in particular I
   should write helper functions to handle the table creation */
void printportoutput(const Target *currenths, const PortList *plist);

/* Prints the MAC address if one was found for the target (generally
   this means that the target is directly connected on an ethernet
   network.  This only prints to human output -- XML is handled by a
   separate call ( print_MAC_XML_Info ) because it needs to be printed
   in a certain place to conform to DTD. */
void printmacinfo(const Target *currenths);

char *logfilename(const char *str, struct tm *tm);

/* Write some information (printf style args) to the given log stream(s).
   Remember to watch out for format string bugs. */
void log_write(int logt, const char *fmt, ...)
     __attribute__ ((format (printf, 2, 3)));

/* This is the workhorse of the logging functions.  Usually it is
   called through log_write(), but it can be called directly if you
   are dealing with a vfprintf-style va_list.  Unlike log_write, YOU
   CAN ONLY CALL THIS WITH ONE LOG TYPE (not a bitmask full of them).
   In addition, YOU MUST SANDWICH EACH EXECUTION OF THIS CALL BETWEEN
   va_start() AND va_end() calls. */
void log_vwrite(int logt, const char *fmt, va_list ap);

/* Close the given log stream(s) */
void log_close(int logt);

/* Flush the given log stream(s).  In other words, all buffered output
   is written to the log immediately */
void log_flush(int logt);

/* Flush every single log stream -- all buffered output is written to the
   corresponding logs immediately */
void log_flush_all();

/* Open a log descriptor of the type given to the filename given.  If
   append is nonzero, the file will be appended instead of clobbered if
   it already exists.  If the file does not exist, it will be created */
int log_open(int logt, bool append, const char *filename);

/* Output the list of ports scanned to the top of machine parseable
   logs (in a comment, unfortunately).  The items in ports should be
   in sequential order for space savings and easier to read output */
void output_ports_to_machine_parseable_output(const struct scan_lists *ports);

/* Return a std::string containing all n strings separated by whitespace, and
   individually quoted if needed. */
std::string join_quoted(const char * const strings[], unsigned int n);

/* Similar to output_ports_to_machine_parseable_output, this function
   outputs the XML version, which is scaninfo records of each scan
   requested and the ports which it will scan for */
void output_xml_scaninfo_records(const struct scan_lists *ports);

/* Writes a heading for a full scan report ("Kmap scan report for..."),
   including host status and DNS records. */
void write_host_header(const Target *currenths);

/* Writes host status info to the log streams (including STDOUT).  An
   example is "Host: 10.11.12.13 (foo.bar.example.com)\tStatus: Up\n" to
   machine log. */
void write_host_status(const Target *currenths);

/* Writes host status info to the XML stream wrapped in a <hosthint> tag */
void write_xml_hosthint(const Target *currenths);

/* Add a <target> element to the XML stating that a target specification was
   ignored. This can be because of, for example, a DNS resolution failure, or a
   syntax error. */
void log_bogus_target(const char *expr);

/* Prints the formatted OS Scan output to stdout, logfiles, etc (but only
   if an OS Scan was performed */
void printosscanoutput(const Target *currenths);

/* Prints the alternate hostname/OS/device information we got from the
   service scan (if it was performed) */
void printserviceinfooutput(const Target *currenths);

#ifndef NOLUA
std::string protect_xml(const std::string s);

/* Use this function to report NSE_PRE_SCAN and NSE_POST_SCAN results */
void printscriptresults(const ScriptResults *scriptResults, stype scantype);

void printhostscriptresults(const Target *currenths);
#endif

/* Print a table with traceroute hops. */
void printtraceroute(const Target *currenths);

/* Print "times for host" output with latency. */
void printtimes(const Target *currenths);

/* Print a detailed list of Kmap interfaces and routes to
   normal/skiddy/stdout output */
int print_iflist(void);

/* Prints a status message while the program is running */
void printStatusMessage();

void print_xml_finished_open(time_t timep, const struct timeval *tv);

void print_xml_hosts();

/* Prints the statistics and other information that goes at the very end
   of an Kmap run */
void printfinaloutput();

/* Prints the names of data files that were loaded and the paths at which they
   were found. */
void printdatafilepaths();

/* nsock logging interface */
void kmap_adjust_loglevel(bool trace);
void kmap_set_nsock_logger();

#endif /* OUTPUT_H */

