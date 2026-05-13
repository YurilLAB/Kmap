/*
 * net_db.cc -- Sharded SQLite database manager for Kmap net-scan.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "net_db.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#ifdef WIN32
#include <windows.h>
#define net_db_sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#define net_db_sleep_ms(ms) usleep((ms) * 1000)
#endif

/* -----------------------------------------------------------------------
 * SQLITE_BUSY retry helper
 *
 * When multiple processes access the same shard concurrently,
 * sqlite3_step() can return SQLITE_BUSY.  This wrapper retries
 * up to NET_DB_BUSY_RETRIES times with NET_DB_BUSY_SLEEP_MS ms
 * between attempts.
 * ----------------------------------------------------------------------- */
#define NET_DB_BUSY_RETRIES  3
#define NET_DB_BUSY_SLEEP_MS 100

static int sqlite3_step_retry(sqlite3_stmt *stmt) {
  int rc = sqlite3_step(stmt);
  for (int attempt = 0; rc == SQLITE_BUSY && attempt < NET_DB_BUSY_RETRIES; ++attempt) {
    net_db_sleep_ms(NET_DB_BUSY_SLEEP_MS);
    sqlite3_reset(stmt);
    rc = sqlite3_step(stmt);
  }
  return rc;
}

/* -----------------------------------------------------------------------
 * IP helpers
 * ----------------------------------------------------------------------- */

uint32_t ip_to_u32(const char *ip_str) {
  unsigned int a, b, c, d;
  if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
    return 0;
  if (a > 255 || b > 255 || c > 255 || d > 255)
    return 0;
  return (a << 24) | (b << 16) | (c << 8) | d;
}

std::string u32_to_ip(uint32_t ip) {
  char buf[16];
  snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
           (ip >> 8) & 0xFF, ip & 0xFF);
  return buf;
}

/* -----------------------------------------------------------------------
 * Shard management
 * ----------------------------------------------------------------------- */

int net_shard_index(uint32_t ip) {
  /* Top 5 bits of the IP → shard 0..31 */
  return static_cast<int>((ip >> 27) & 0x1F);
}

std::string net_shard_path(const char *data_dir, int shard_idx) {
  char buf[512];
  snprintf(buf, sizeof(buf), "%s/shard_%03d.db", data_dir, shard_idx);
  return buf;
}

/* Schema creation SQL */
static const char *SCHEMA_SQL =
  "CREATE TABLE IF NOT EXISTS hosts ("
  "  ip                   TEXT NOT NULL,"
  "  port                 INTEGER NOT NULL,"
  "  proto                TEXT DEFAULT 'tcp',"
  "  first_seen           INTEGER NOT NULL,"
  "  last_seen            INTEGER NOT NULL,"
  "  service              TEXT,"
  "  version              TEXT,"
  "  cves                 TEXT,"
  "  web_title            TEXT,"
  "  web_server           TEXT,"
  "  web_headers          TEXT,"
  "  web_paths            TEXT,"
  "  asn                  INTEGER DEFAULT 0,"
  "  as_name              TEXT,"
  "  country              TEXT,"
  "  bgp_prefix           TEXT,"
  "  enriched             INTEGER DEFAULT 0,"
  "  enrichment_error     TEXT,"
  "  enrichment_error_at  INTEGER DEFAULT 0,"
  /* v4 patch-status columns. Listed here for fresh-install databases;
     existing dbs pick them up via the MIGRATIONS array below. */
  "  enriched_at          INTEGER DEFAULT 0,"
  "  prev_cves            TEXT,"
  "  prev_service         TEXT,"
  "  prev_version         TEXT,"
  "  prev_enriched_at     INTEGER DEFAULT 0,"
  "  scan_count           INTEGER DEFAULT 1,"
  /* v4 enrichment-data persistence columns. Mirrors of the MIGRATIONS
     entries below — kept on fresh-install schemas so a brand-new DB
     does not have to ALTER through the upgrade chain. */
  "  hostname               TEXT,"
  "  powered_by             TEXT,"
  "  x_generator            TEXT,"
  "  redirect_target        TEXT,"
  "  robots_disallowed_json TEXT,"
  "  screenshot_path        TEXT,"
  "  asn_registry           TEXT,"
  "  asn_region             TEXT,"
  /* v5 TLS cert columns. tls_self_signed is tri-state and intentionally
     has no DEFAULT so legacy/never-probed rows stay NULL ("unknown")
     rather than falsely "chain-validated". */
  "  tls_subject_cn         TEXT,"
  "  tls_issuer             TEXT,"
  "  tls_san_json           TEXT,"
  "  tls_not_after          TEXT,"
  "  tls_self_signed        INTEGER,"
  "  tls_protocol           TEXT,"
  "  tls_sha256             TEXT,"
  "  PRIMARY KEY (ip, port)"
  ");"
  /* Indexes whose columns have always existed since v1 are safe in
     SCHEMA_SQL.  Indexes on columns added by later migrations live in
     POST_MIGRATION_SQL so old databases reach the migration step before
     the index is attempted. */
  "CREATE INDEX IF NOT EXISTS idx_hosts_port     ON hosts(port);"
  "CREATE INDEX IF NOT EXISTS idx_hosts_service  ON hosts(service);"
  "CREATE INDEX IF NOT EXISTS idx_hosts_enriched ON hosts(enriched);"
  "CREATE INDEX IF NOT EXISTS idx_hosts_lastseen ON hosts(last_seen);";

/* Per-statement migrations applied to pre-existing databases.  ALTER TABLE
   ADD COLUMN errors out if the column already exists; we run each statement
   in its own sqlite3_exec() so a single failure does not skip the others. */
static const char *MIGRATIONS[] = {
  /* v2: ASN/GeoIP columns */
  "ALTER TABLE hosts ADD COLUMN asn INTEGER DEFAULT 0",
  "ALTER TABLE hosts ADD COLUMN as_name TEXT",
  "ALTER TABLE hosts ADD COLUMN country TEXT",
  "ALTER TABLE hosts ADD COLUMN bgp_prefix TEXT",
  /* v3: enrichment-error tracking for retry-after-cooldown */
  "ALTER TABLE hosts ADD COLUMN enrichment_error TEXT",
  "ALTER TABLE hosts ADD COLUMN enrichment_error_at INTEGER DEFAULT 0",
  /* v4a: patch-status / re-scan history. enriched_at is when the current
     cves/service were stored; prev_* hold the state captured atomically
     on the next enrichment so reports can diff "patched since last scan"
     without keeping a separate history table. scan_count is bumped by
     the insert-host UPSERT on every re-discovery. */
  "ALTER TABLE hosts ADD COLUMN enriched_at INTEGER DEFAULT 0",
  "ALTER TABLE hosts ADD COLUMN prev_cves TEXT",
  "ALTER TABLE hosts ADD COLUMN prev_service TEXT",
  "ALTER TABLE hosts ADD COLUMN prev_version TEXT",
  "ALTER TABLE hosts ADD COLUMN prev_enriched_at INTEGER DEFAULT 0",
  "ALTER TABLE hosts ADD COLUMN scan_count INTEGER DEFAULT 1",
  /* v4b: persist enrichment data the pipeline already collected but had
     been discarding at the persistence boundary.
     hostname     — reverse DNS (PTR), per-IP identity key.
     powered_by   — HTTP X-Powered-By header (extracted but only stashed in JSON).
     x_generator  — HTTP X-Generator header (same).
     redirect_target — HTTP Location: from / for the root.
     robots_disallowed_json — JSON array of robots.txt disallow paths.
     screenshot_path — path to PNG saved by run_screenshot_capture.
     asn_registry — RIR from AsnInfo (arin/ripe/etc.).
     asn_region   — region from AsnInfo. */
  "ALTER TABLE hosts ADD COLUMN hostname TEXT",
  "ALTER TABLE hosts ADD COLUMN powered_by TEXT",
  "ALTER TABLE hosts ADD COLUMN x_generator TEXT",
  "ALTER TABLE hosts ADD COLUMN redirect_target TEXT",
  "ALTER TABLE hosts ADD COLUMN robots_disallowed_json TEXT",
  "ALTER TABLE hosts ADD COLUMN screenshot_path TEXT",
  "ALTER TABLE hosts ADD COLUMN asn_registry TEXT",
  "ALTER TABLE hosts ADD COLUMN asn_region TEXT",
  /* v5: TLS columns — populated by web_recon and the net_enrich
     tls_capture_cert handshake leg. */
  "ALTER TABLE hosts ADD COLUMN tls_subject_cn TEXT",
  "ALTER TABLE hosts ADD COLUMN tls_issuer TEXT",
  "ALTER TABLE hosts ADD COLUMN tls_san_json TEXT",
  "ALTER TABLE hosts ADD COLUMN tls_not_after TEXT",
  /* tls_self_signed is tri-state: NULL = no TLS data captured (legacy/
     never-probed rows backfill to NULL), 0 = chain-validated, 1 = self-
     signed.  Do NOT add a DEFAULT — that would silently mark every
     never-probed legacy row as "TLS checked, not self-signed". */
  "ALTER TABLE hosts ADD COLUMN tls_self_signed INTEGER",
  "ALTER TABLE hosts ADD COLUMN tls_protocol TEXT",
  "ALTER TABLE hosts ADD COLUMN tls_sha256 TEXT",
};

sqlite3 *net_db_open(const std::string &path) {
  sqlite3 *db = nullptr;
  int rc = sqlite3_open(path.c_str(), &db);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "net-scan: cannot open database %s: %s\n",
            path.c_str(), db ? sqlite3_errmsg(db) : "unknown error");
    if (db) sqlite3_close(db);
    return nullptr;
  }

  /* Performance pragmas for bulk insert workloads */
  sqlite3_exec(db, "PRAGMA journal_mode=WAL", nullptr, nullptr, nullptr);
  sqlite3_exec(db, "PRAGMA synchronous=NORMAL", nullptr, nullptr, nullptr);
  sqlite3_exec(db, "PRAGMA cache_size=-64000", nullptr, nullptr, nullptr);
  sqlite3_exec(db, "PRAGMA temp_store=MEMORY", nullptr, nullptr, nullptr);

  /* Create schema */
  char *errmsg = nullptr;
  rc = sqlite3_exec(db, SCHEMA_SQL, nullptr, nullptr, &errmsg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "net-scan: schema creation failed: %s\n",
            errmsg ? errmsg : "unknown error");
    sqlite3_free(errmsg);
    sqlite3_close(db);
    return nullptr;
  }

  /* Migrate existing databases by running each ADD COLUMN independently.
   * "duplicate column" errors mean the column already exists -- ignore them. */
  for (const char *stmt : MIGRATIONS) {
    sqlite3_exec(db, stmt, nullptr, nullptr, nullptr);
  }
  /* Indexes that depend on migration-added columns -- now safe to create. */
  sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_hosts_asn ON hosts(asn)",
               nullptr, nullptr, nullptr);
  sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_hosts_country ON hosts(country)",
               nullptr, nullptr, nullptr);
  sqlite3_exec(db,
    "CREATE INDEX IF NOT EXISTS idx_hosts_err_at ON hosts(enrichment_error_at)",
    nullptr, nullptr, nullptr);
  /* v4/v5 pivot-key indexes — relationship matching looks up cohorts of IPs
     by these values, so they need to be cheap.  hostname can pivot across
     wildcard zones; tls_sha256 fingerprints the actual server certificate. */
  sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname)",
               nullptr, nullptr, nullptr);
  sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_hosts_tls_sha256 ON hosts(tls_sha256)",
               nullptr, nullptr, nullptr);

  return db;
}

void net_db_close(sqlite3 *db) {
  if (db) sqlite3_close(db);
}

/* -----------------------------------------------------------------------
 * Host records
 * ----------------------------------------------------------------------- */

int net_db_insert_host(sqlite3 *db, uint32_t ip, int port,
                       const char *proto, int64_t timestamp) {
  if (!db) return -1;

  /* UPSERT semantics: on first sight, insert with first_seen=last_seen=ts
     and scan_count=1. On re-discovery, leave first_seen alone (it is the
     historical anchor) but refresh last_seen and bump scan_count. The
     prior INSERT OR IGNORE form left last_seen frozen at the first-seen
     time, which made "did I see this host on the latest scan" impossible
     to answer from the DB without re-running the discovery. ON CONFLICT
     ... DO UPDATE has been in SQLite since 3.24 (2018-06); the bundled
     amalgamation is far newer. */
  static const char *sql =
    "INSERT INTO hosts (ip, port, proto, first_seen, last_seen, scan_count) "
    "VALUES (?, ?, ?, ?, ?, 1) "
    "ON CONFLICT(ip, port) DO UPDATE SET "
    "  last_seen  = excluded.last_seen, "
    "  scan_count = scan_count + 1";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;

  std::string ip_str = u32_to_ip(ip);
  sqlite3_bind_text(stmt, 1, ip_str.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 2, port);
  sqlite3_bind_text(stmt, 3, proto, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 4, timestamp);
  sqlite3_bind_int64(stmt, 5, timestamp);

  int rc = sqlite3_step_retry(stmt);
  sqlite3_finalize(stmt);

  if (rc == SQLITE_DONE) {
    /* sqlite3_changes counts rows affected by either the INSERT or the
       UPSERT branch, so 1 means "row written" regardless of new vs
       updated. Callers that need to distinguish (e.g. progress counters
       for "first sight" vs "re-discovery") should check scan_count
       separately via net_db_get_host. */
    return sqlite3_changes(db) > 0 ? 1 : 0;
  }
  return -1;
}

int net_db_update_enrichment(sqlite3 *db, const char *ip, int port,
                             const char *service, const char *version,
                             const char *cves_json,
                             const char *web_title, const char *web_server,
                             const char *web_headers, const char *web_paths,
                             const char *powered_by,
                             const char *x_generator,
                             const char *redirect_target,
                             const char *robots_disallowed_json) {
  if (!db) return -1;

  /* Atomic prev-state capture: when this row was already enriched at
     least once (enriched=1), copy the current cves/service/version/
     enriched_at into prev_* BEFORE overwriting with the new values.
     One UPDATE statement, so the snapshot can never get out of sync
     with the new data even under concurrent SQLITE_BUSY retries. The
     CASE-WHEN guard means a *first*-time enrichment leaves prev_* at
     their default empty / zero values, so reports can use "prev_cves
     non-empty" as the trigger for the patch-status section.

     COALESCE on the v4b fields (powered_by, x_generator, redirect_target,
     robots_disallowed_json) preserves prior data when the caller passes
     NULL — callers without the data yet can leave the cells untouched
     instead of wiping good values on retry. The CASE-WHEN and COALESCE
     branches read the row's pre-update state because SQLite evaluates
     the entire SET right-hand side before any assignment takes effect. */
  static const char *sql =
    "UPDATE hosts SET "
    "  prev_cves        = CASE WHEN enriched=1 THEN cves        ELSE prev_cves        END, "
    "  prev_service     = CASE WHEN enriched=1 THEN service     ELSE prev_service     END, "
    "  prev_version     = CASE WHEN enriched=1 THEN version     ELSE prev_version     END, "
    "  prev_enriched_at = CASE WHEN enriched=1 THEN enriched_at ELSE prev_enriched_at END, "
    "  service=?, version=?, cves=?, web_title=?, "
    "  web_server=?, web_headers=?, web_paths=?, "
    "  powered_by             = COALESCE(?, powered_by), "
    "  x_generator            = COALESCE(?, x_generator), "
    "  redirect_target        = COALESCE(?, redirect_target), "
    "  robots_disallowed_json = COALESCE(?, robots_disallowed_json), "
    "  enriched=1, "
    "  enriched_at=strftime('%s','now'), "
    "  enrichment_error=NULL, enrichment_error_at=0, "
    "  last_seen=strftime('%s','now') "
    "WHERE ip=? AND port=?";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;

  auto bind_or_null = [&](int idx, const char *val) {
    if (val && val[0])
      sqlite3_bind_text(stmt, idx, val, -1, SQLITE_TRANSIENT);
    else
      sqlite3_bind_null(stmt, idx);
  };

  bind_or_null(1,  service);
  bind_or_null(2,  version);
  bind_or_null(3,  cves_json);
  bind_or_null(4,  web_title);
  bind_or_null(5,  web_server);
  bind_or_null(6,  web_headers);
  bind_or_null(7,  web_paths);
  bind_or_null(8,  powered_by);
  bind_or_null(9,  x_generator);
  bind_or_null(10, redirect_target);
  bind_or_null(11, robots_disallowed_json);
  sqlite3_bind_text(stmt, 12, ip, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 13, port);

  int rc = sqlite3_step_retry(stmt);
  sqlite3_finalize(stmt);
  return (rc == SQLITE_DONE) ? 0 : -1;
}

int net_db_record_enrichment_error(sqlite3 *db, const char *ip, int port,
                                   const char *error_msg) {
  if (!db || !ip) return -1;

  static const char *sql =
    "UPDATE hosts SET enrichment_error=?, "
    "enrichment_error_at=strftime('%s','now') "
    "WHERE ip=? AND port=?";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;

  if (error_msg && error_msg[0])
    sqlite3_bind_text(stmt, 1, error_msg, -1, SQLITE_TRANSIENT);
  else
    sqlite3_bind_null(stmt, 1);
  sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, port);

  int rc = sqlite3_step_retry(stmt);
  sqlite3_finalize(stmt);
  return (rc == SQLITE_DONE) ? 0 : -1;
}

int net_db_update_asn(sqlite3 *db, const char *ip,
                      uint32_t asn, const char *as_name,
                      const char *country, const char *bgp_prefix,
                      const char *asn_registry, const char *asn_region) {
  if (!db || !ip) return -1;

  /* COALESCE on registry/region so legacy callers without those values can
     still update asn/as_name/country/bgp_prefix without wiping previously-
     captured registry data. */
  static const char *sql =
    "UPDATE hosts SET asn=?, as_name=?, country=?, bgp_prefix=?, "
    "asn_registry=COALESCE(?, asn_registry), "
    "asn_region=COALESCE(?, asn_region) "
    "WHERE ip=?";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;

  /* ASN is uint32_t (4-byte ASNs go up to 4,294,967,295). Binding via
   * sqlite3_bind_int would truncate values above INT_MAX to a negative
   * integer in storage, which round-trips by accident through column_int
   * + uint32_t cast but breaks any SQL that filters by asn directly. Use
   * int64 to preserve the full unsigned range. */
  sqlite3_bind_int64(stmt, 1, static_cast<int64_t>(asn));
  auto bind_or_null = [&](int idx, const char *val) {
    if (val && val[0])
      sqlite3_bind_text(stmt, idx, val, -1, SQLITE_TRANSIENT);
    else
      sqlite3_bind_null(stmt, idx);
  };
  bind_or_null(2, as_name);
  bind_or_null(3, country);
  bind_or_null(4, bgp_prefix);
  bind_or_null(5, asn_registry);
  bind_or_null(6, asn_region);
  sqlite3_bind_text(stmt, 7, ip, -1, SQLITE_TRANSIENT);

  int rc = sqlite3_step_retry(stmt);
  sqlite3_finalize(stmt);
  return (rc == SQLITE_DONE) ? 0 : -1;
}

/* -----------------------------------------------------------------------
 * v4/v5 helpers — hostname, screenshot path, TLS cert details
 * ----------------------------------------------------------------------- */

int net_db_set_hostname(sqlite3 *db, const char *ip, const char *hostname) {
  if (!db || !ip) return -1;

  static const char *sql = "UPDATE hosts SET hostname=? WHERE ip=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;

  if (hostname && hostname[0])
    sqlite3_bind_text(stmt, 1, hostname, -1, SQLITE_TRANSIENT);
  else
    sqlite3_bind_null(stmt, 1);
  sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_TRANSIENT);

  int rc = sqlite3_step_retry(stmt);
  sqlite3_finalize(stmt);
  return (rc == SQLITE_DONE) ? 0 : -1;
}

int net_db_set_screenshot(sqlite3 *db, const char *ip, int port,
                          const char *screenshot_path) {
  if (!db || !ip) return -1;

  static const char *sql =
    "UPDATE hosts SET screenshot_path=? WHERE ip=? AND port=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;

  if (screenshot_path && screenshot_path[0])
    sqlite3_bind_text(stmt, 1, screenshot_path, -1, SQLITE_TRANSIENT);
  else
    sqlite3_bind_null(stmt, 1);
  sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, port);

  int rc = sqlite3_step_retry(stmt);
  sqlite3_finalize(stmt);
  return (rc == SQLITE_DONE) ? 0 : -1;
}

int net_db_update_tls(sqlite3 *db, const char *ip, int port,
                      const char *tls_subject_cn,
                      const char *tls_issuer,
                      const char *tls_san_json,
                      const char *tls_not_after,
                      int tls_self_signed,
                      const char *tls_protocol,
                      const char *tls_sha256) {
  if (!db || !ip) return -1;

  /* COALESCE every text field so partial TLS info (e.g. handshake completes
     but cert chain parsing fails) does not wipe prior good data.  The
     self-signed flag uses -1 as the "leave unchanged" sentinel. */
  static const char *sql =
    "UPDATE hosts SET "
    "tls_subject_cn=COALESCE(?, tls_subject_cn), "
    "tls_issuer=COALESCE(?, tls_issuer), "
    "tls_san_json=COALESCE(?, tls_san_json), "
    "tls_not_after=COALESCE(?, tls_not_after), "
    "tls_self_signed=COALESCE(?, tls_self_signed), "
    "tls_protocol=COALESCE(?, tls_protocol), "
    "tls_sha256=COALESCE(?, tls_sha256) "
    "WHERE ip=? AND port=?";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;

  auto bind_or_null = [&](int idx, const char *val) {
    if (val && val[0])
      sqlite3_bind_text(stmt, idx, val, -1, SQLITE_TRANSIENT);
    else
      sqlite3_bind_null(stmt, idx);
  };

  bind_or_null(1, tls_subject_cn);
  bind_or_null(2, tls_issuer);
  bind_or_null(3, tls_san_json);
  bind_or_null(4, tls_not_after);
  if (tls_self_signed < 0)
    sqlite3_bind_null(stmt, 5);
  else
    sqlite3_bind_int(stmt, 5, tls_self_signed ? 1 : 0);
  bind_or_null(6, tls_protocol);
  bind_or_null(7, tls_sha256);
  sqlite3_bind_text(stmt, 8, ip, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 9, port);

  int rc = sqlite3_step_retry(stmt);
  sqlite3_finalize(stmt);
  return (rc == SQLITE_DONE) ? 0 : -1;
}

std::vector<std::string> net_db_get_unenriched(sqlite3 *db, int limit,
                                               int64_t retry_after_seconds) {
  std::vector<std::string> ips;
  if (!db) return ips;

  /* Pick rows that are not yet enriched AND either have never errored
     or whose last error is older than the retry window. */
  static const char *sql =
    "SELECT DISTINCT ip FROM hosts "
    "WHERE enriched=0 "
    "  AND (enrichment_error_at = 0 "
    "       OR enrichment_error_at <= strftime('%s','now') - ?) "
    "LIMIT ?";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return ips;

  sqlite3_bind_int64(stmt, 1, retry_after_seconds);
  sqlite3_bind_int(stmt, 2, limit);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *txt = sqlite3_column_text(stmt, 0);
    if (txt) ips.emplace_back(reinterpret_cast<const char *>(txt));
  }
  sqlite3_finalize(stmt);
  return ips;
}

std::vector<NetHost> net_db_get_host(sqlite3 *db, const char *ip) {
  std::vector<NetHost> hosts;
  if (!db || !ip) return hosts;

  /* Selects v4 patch-status columns and v4b/v5 enrichment columns
     alongside the existing fields.  The COALESCE on the patch-status
     columns lets this run cleanly against any post-migration database
     (where the columns exist but rows seen before v4 have NULLs).
     The v4b/v5 columns can be read with bare names because the struct
     stores them as std::string / int and a NULL DB cell just yields
     an empty string or the -1 tri-state sentinel for tls_self_signed. */
  static const char *sql =
    "SELECT ip, port, proto, first_seen, last_seen, service, version, "
    "cves, web_title, web_server, web_headers, web_paths, "
    "asn, as_name, country, bgp_prefix, enriched, "
    "COALESCE(prev_cves, ''), COALESCE(prev_service, ''), "
    "COALESCE(prev_version, ''), COALESCE(prev_enriched_at, 0), "
    "COALESCE(enriched_at, 0), COALESCE(scan_count, 1), "
    "hostname, powered_by, x_generator, redirect_target, "
    "robots_disallowed_json, screenshot_path, asn_registry, asn_region, "
    "tls_subject_cn, tls_issuer, tls_san_json, tls_not_after, "
    "tls_self_signed, tls_protocol, tls_sha256 "
    "FROM hosts WHERE ip=?";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return hosts;

  sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);

  auto col = [&](int c) -> std::string {
    const unsigned char *p = sqlite3_column_text(stmt, c);
    return p ? reinterpret_cast<const char *>(p) : "";
  };

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    NetHost h;
    h.ip          = col(0);
    h.port        = sqlite3_column_int(stmt, 1);
    h.proto       = col(2);
    h.first_seen  = sqlite3_column_int64(stmt, 3);
    h.last_seen   = sqlite3_column_int64(stmt, 4);
    h.service     = col(5);
    h.version     = col(6);
    h.cves        = col(7);
    h.web_title   = col(8);
    h.web_server  = col(9);
    h.web_headers = col(10);
    h.web_paths   = col(11);
    /* Read as int64 to match the int64 bind in net_db_update_asn -- see
     * note there. */
    h.asn         = static_cast<uint32_t>(sqlite3_column_int64(stmt, 12));
    h.as_name     = col(13);
    h.country     = col(14);
    h.bgp_prefix  = col(15);
    h.enriched    = sqlite3_column_int(stmt, 16);
    h.prev_cves        = col(17);
    h.prev_service     = col(18);
    h.prev_version     = col(19);
    h.prev_enriched_at = sqlite3_column_int64(stmt, 20);
    h.enriched_at      = sqlite3_column_int64(stmt, 21);
    h.scan_count       = sqlite3_column_int(stmt, 22);
    h.hostname               = col(23);
    h.powered_by             = col(24);
    h.x_generator            = col(25);
    h.redirect_target        = col(26);
    h.robots_disallowed_json = col(27);
    h.screenshot_path        = col(28);
    h.asn_registry           = col(29);
    h.asn_region             = col(30);
    h.tls_subject_cn         = col(31);
    h.tls_issuer             = col(32);
    h.tls_san_json           = col(33);
    h.tls_not_after          = col(34);
    /* Preserve the NULL/0/1 tri-state — column_int returns 0 for NULL,
       which would conflate "unknown" with "verified not self-signed". */
    h.tls_self_signed = (sqlite3_column_type(stmt, 35) == SQLITE_NULL)
                         ? -1 : sqlite3_column_int(stmt, 35);
    h.tls_protocol           = col(36);
    h.tls_sha256             = col(37);
    hosts.push_back(std::move(h));
  }
  sqlite3_finalize(stmt);
  return hosts;
}

int64_t net_db_count(sqlite3 *db) {
  if (!db) return -1;
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM hosts", -1, &stmt, nullptr) != SQLITE_OK)
    return -1;
  int64_t count = 0;
  if (sqlite3_step(stmt) == SQLITE_ROW)
    count = sqlite3_column_int64(stmt, 0);
  sqlite3_finalize(stmt);
  return count;
}

int64_t net_db_count_unenriched(sqlite3 *db, int64_t retry_after_seconds) {
  if (!db) return -1;
  static const char *sql =
    "SELECT COUNT(*) FROM hosts "
    "WHERE enriched=0 "
    "  AND (enrichment_error_at = 0 "
    "       OR enrichment_error_at <= strftime('%s','now') - ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;
  sqlite3_bind_int64(stmt, 1, retry_after_seconds);
  int64_t count = 0;
  if (sqlite3_step(stmt) == SQLITE_ROW)
    count = sqlite3_column_int64(stmt, 0);
  sqlite3_finalize(stmt);
  return count;
}

/* -----------------------------------------------------------------------
 * Batch operations
 * ----------------------------------------------------------------------- */

void net_db_begin(sqlite3 *db) {
  if (!db) return;
  char *errmsg = nullptr;
  int rc = sqlite3_exec(db, "BEGIN TRANSACTION", nullptr, nullptr, &errmsg);
  if (rc != SQLITE_OK && errmsg) {
    fprintf(stderr, "net-scan: WARNING: BEGIN TRANSACTION failed: %s\n", errmsg);
    sqlite3_free(errmsg);
  }
}

void net_db_commit(sqlite3 *db) {
  if (!db) return;
  char *errmsg = nullptr;
  int rc = sqlite3_exec(db, "COMMIT", nullptr, nullptr, &errmsg);
  if (rc != SQLITE_OK && errmsg) {
    fprintf(stderr, "net-scan: WARNING: COMMIT failed: %s\n", errmsg);
    sqlite3_free(errmsg);
  }
}

/* -----------------------------------------------------------------------
 * CVE id parser + diff helpers
 *
 * The CVE column is a JSON array written by net_enrich's cves_to_json,
 * shaped like [{"id":"CVE-2024-...","cvss":...,"severity":"...",
 * "desc":"..."},...]. For patch-status we only need the IDs, so a full
 * JSON parse is overkill. The walk below is intentionally state-machine
 * lite: it scans for the literal "id":" prefix at the start of each
 * object and reads characters until the closing quote, treating any
 * "id" inside the desc field as a non-issue because we anchor the
 * search to immediately after a '{' (which a desc field cannot contain
 * unescaped per net_enrich's json_escape).
 *
 * Tolerant of whitespace between tokens, "[]" empty arrays, NULL/empty
 * input, and missing fields. Pure -- no DB access -- so it can be
 * unit-tested without a fixture.
 * ----------------------------------------------------------------------- */

std::vector<std::string> net_db_parse_cve_ids(const std::string &cves_json) {
  std::vector<std::string> ids;
  if (cves_json.empty() || cves_json == "[]") return ids;

  size_t pos = 0;
  while (pos < cves_json.size()) {
    /* Find next object opener. Only an unescaped '{' starts a new entry;
       a '{' inside a quoted string never appears because json_escape
       does not allow raw '{' inside descriptions but does keep them
       readable -- still, anchoring to '{' right after the array element
       boundary is robust enough for the format we control. */
    size_t obj_start = cves_json.find('{', pos);
    if (obj_start == std::string::npos) break;

    /* Find the matching '}' to bound this entry. The simple scan works
       because json_escape strips control characters and the only
       structural braces in our format are the per-entry object braces;
       no nested objects appear. */
    size_t obj_end = cves_json.find('}', obj_start);
    if (obj_end == std::string::npos) break;

    /* Within this entry, look for "id":" then read up to the next
       unescaped quote. We respect the same odd/even backslash rule
       json_extract_string in net_report uses for full correctness on
       descriptions containing literal backslashes -- though IDs
       themselves never contain a backslash, the parser must not get
       desynchronized by one in a sibling field that comes BEFORE id. */
    static const char id_key[] = "\"id\":\"";
    size_t key = cves_json.find(id_key, obj_start);
    if (key == std::string::npos || key > obj_end) {
      pos = obj_end + 1;
      continue;
    }
    size_t id_start = key + sizeof(id_key) - 1;
    size_t id_end = id_start;
    while (id_end < obj_end) {
      id_end = cves_json.find('"', id_end);
      if (id_end == std::string::npos || id_end > obj_end) break;
      /* Count the run of consecutive backslashes immediately preceding
         this quote. An odd run means the quote is escaped (every
         backslash pairs except one, which escapes the quote); an even
         run means the backslashes pair off and the quote terminates
         the string. The mod-2 form is used in place of `bs & 1u` to
         avoid any signed/unsigned mismatch warnings under MSVC's
         default Level 2 diagnostics. */
      size_t bs = 0;
      size_t k = id_end;
      while (k > id_start && cves_json[k - 1] == '\\') { bs++; k--; }
      if ((bs % 2) == 0) break;  /* unescaped quote */
      id_end++;
    }
    if (id_end != std::string::npos && id_end > id_start && id_end <= obj_end) {
      ids.emplace_back(cves_json.substr(id_start, id_end - id_start));
    }
    pos = obj_end + 1;
  }
  return ids;
}

NetDbCveDiff net_db_cve_diff(const std::string &prev_cves_json,
                             const std::string &current_cves_json) {
  NetDbCveDiff out;

  std::vector<std::string> prev_ids = net_db_parse_cve_ids(prev_cves_json);
  std::vector<std::string> cur_ids  = net_db_parse_cve_ids(current_cves_json);

  /* Sort + dedupe each side so set arithmetic is O(n+m) rather than
     O(n*m). Stable order also gives reproducible report output. The
     two-call inline form is used in place of a local lambda helper so
     no anonymous function-object class is generated -- some MSVC
     toolchains have historically produced odd diagnostics when a
     non-capturing lambda is invoked twice on the same TU and the
     name-mangling collides. The cost is ~6 extra lines for clarity. */
  std::sort(prev_ids.begin(), prev_ids.end());
  prev_ids.erase(std::unique(prev_ids.begin(), prev_ids.end()),
                 prev_ids.end());
  std::sort(cur_ids.begin(), cur_ids.end());
  cur_ids.erase(std::unique(cur_ids.begin(), cur_ids.end()),
                cur_ids.end());

  /* Three-way merge: walk both sorted lists in lockstep, emitting into
     persisting / introduced / patched depending on which side(s) the
     id appears on. */
  size_t i = 0, j = 0;
  while (i < prev_ids.size() && j < cur_ids.size()) {
    int cmp = prev_ids[i].compare(cur_ids[j]);
    if (cmp == 0) {
      out.persisting.push_back(prev_ids[i]);
      i++; j++;
    } else if (cmp < 0) {
      out.patched.push_back(prev_ids[i]);
      i++;
    } else {
      out.introduced.push_back(cur_ids[j]);
      j++;
    }
  }
  while (i < prev_ids.size()) out.patched.push_back(prev_ids[i++]);
  while (j < cur_ids.size())  out.introduced.push_back(cur_ids[j++]);

  return out;
}
