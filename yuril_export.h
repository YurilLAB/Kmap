#ifndef KMAP_YURIL_EXPORT_H
#define KMAP_YURIL_EXPORT_H

/*
 * yuril_export.h -- Stable export contract between Kmap and the Yuril
 * Security Suite (YurilTracking / YurilAntivirus / Lockdown).
 *
 * When --yuril-export <dir> is supplied, Kmap writes two files in <dir>:
 *
 *   kmap-yuril-export.json       Full scan data (extends the --json output
 *                                with cves, default_creds, web_recon
 *                                sections and a top-level schema_version
 *                                and export_type field).
 *
 *   kmap-yuril-export.meta.json  Integrity metadata:
 *                                  - schema_version  (int)
 *                                  - produced_at     (ISO-8601 UTC)
 *                                  - kmap_version    (string)
 *                                  - sha256          (lowercase hex of .json)
 *                                  - host_count      (int)
 *                                  - cve_count       (int)
 *
 * The .meta.json lets consumers verify the data file has not been
 * truncated or tampered with before importing it. Both files are
 * written atomically (tmpfile + rename).
 *
 * USAGE
 * -----
 * Mirrors the json_* streaming API so host data can be serialized and
 * released as the scan progresses (Kmap frees Target objects per host).
 *
 *   yuril_export_initialize(dir);
 *   yuril_export_write_scaninfo(version, args, start_time);
 *   for each host:
 *       yuril_export_write_host(target);
 *   yuril_export_write_stats(up, down, total, elapsed);
 *   yuril_export_finalize();
 *
 * SCHEMA VERSION POLICY
 * ---------------------
 * Bump KMAP_YURIL_SCHEMA_VERSION when the data contract changes in a
 * way that older consumers cannot ignore. Additive-only changes (new
 * optional fields) do NOT require a version bump.
 */

#include "Target.h"

/* Integer schema version for the export contract.               */
/* v1: hosts/ports/services/os + cves/default_creds/web_recon.   */
#define KMAP_YURIL_SCHEMA_VERSION 1

/* Canonical filenames within the --yuril-export <dir>. */
#define KMAP_YURIL_EXPORT_DATA_FILE "kmap-yuril-export.json"
#define KMAP_YURIL_EXPORT_META_FILE "kmap-yuril-export.meta.json"

/* Initialize the exporter and record the target directory. The directory
   must already exist; a write-probe is performed up front so failures are
   surfaced before the scan rather than after. Silently does nothing when
   out_dir is null or empty. */
void yuril_export_initialize(const char *out_dir);

/* Record top-level scanner metadata (version, invocation args, start time). */
void yuril_export_write_scaninfo(const char *kmap_version,
                                 const char *args,
                                 long start_time);

/* Append a single scanned host (addresses, ports, OS, CVEs, creds, web).
   Must be called after yuril_export_initialize() and before finalize(). */
void yuril_export_write_host(const Target *t);

/* Record summary statistics. */
void yuril_export_write_stats(int up, int down, int total, float elapsed);

/* Serialize, hash, and atomically write the data + metadata files to the
   directory chosen in yuril_export_initialize(). Safe to call even if
   yuril_export_initialize was not called (no-op). */
void yuril_export_finalize(void);

#endif /* KMAP_YURIL_EXPORT_H */
