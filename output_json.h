
/***************************************************************************
 * output_json.h -- JSON output serializer for Kmap scan results.          *
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

#ifndef OUTPUT_JSON_H
#define OUTPUT_JSON_H

#include "Target.h"
#include "third-party/nlohmann/json.hpp"

/* Build the canonical per-host JSON object used by both --json and
   --yuril-export. Exposed so consumers like yuril_export.cc can reuse
   the exact same host serialization. */
nlohmann::json build_host_json(const Target *t);

/* Call these in order during a scan to produce a JSON output file. */

/* Initialize the JSON document and record the output filename.
   Must be called before any other json_* function. */
void json_initialize(const char *filename);

/* Record top-level kmap metadata: scanner version, command-line args,
   and the epoch start time of the scan. */
void json_write_scaninfo(const char *version, const char *args, long start_time);

/* Serialize a single scanned host (addresses, hostnames, ports, OS) and
   append it to the "hosts" array in the document. */
void json_write_host(const Target *t);

/* Record summary statistics at the end of the run. */
void json_write_stats(int up, int down, int total, float elapsed);

/* Write the accumulated JSON document to the file chosen in
   json_initialize() and release all associated resources. */
void json_finalize();

/* -----------------------------------------------------------------------
 * Scan report output (--report)
 *
 * Generates a styled .txt or .md report depending on the file extension.
 * ----------------------------------------------------------------------- */

/* Initialize the report file.  Extension determines format:
   ".md" → Markdown, anything else → styled plain text. */
void report_initialize(const char *filename);

/* Record a single host's data into the report. */
void report_write_host(const Target *t);

/* Write summary statistics and finalize the report file. */
void report_write_stats(int up, int down, int total, float elapsed);

/* Flush and close the report file. */
void report_finalize();

#endif /* OUTPUT_JSON_H */
