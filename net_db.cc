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
  "CREATE INDEX IF NOT EXISTS idx_hosts_lastseen ON hosts(last_seen);"
  /* v5b: fingerprints — per-shard relationship-matching index.
     ip_u32 INTEGER (4 bytes vs ~15 for dotted-quad TEXT) keeps the row
     compact since this table easily out-rows the hosts table after a
     full-internet scan (one host can carry 5–20 fingerprints).
     Primary key is (ip_u32, kind, value) — ports collapse, so a host
     serving the same cert on 443 and 8443 yields one row, not two.
     port stays as informational metadata (set to the most recent
     observation) and is intentionally NOT part of the PK. */
  "CREATE TABLE IF NOT EXISTS fingerprints ("
  "  ip_u32       INTEGER NOT NULL,"
  "  kind         TEXT    NOT NULL,"
  "  value        TEXT    NOT NULL,"
  "  port         INTEGER,"
  "  observed_at  INTEGER NOT NULL,"
  "  PRIMARY KEY (ip_u32, kind, value)"
  ");"
  /* Inverse lookup is the hot path: "given a (kind, value), who else
     carries it?".  Without this composite index that query falls back
     to a full table scan, which dies on a 10B-row table. */
  "CREATE INDEX IF NOT EXISTS idx_fp_kind_value ON fingerprints(kind, value);"
  /* Forward lookup: every fingerprint a given IP carries.  Covered by
     the PK leading column already, but an explicit single-column index
     keeps the query planner from second-guessing under varied stats. */
  "CREATE INDEX IF NOT EXISTS idx_fp_ip         ON fingerprints(ip_u32);"
  /* v5c: persistent topology graph — nodes and edges that survive
     across runs so successive tracemap invocations refine the same
     graph instead of starting from scratch.  See the comment block
     above NetTopoNode in net_db.h for compression rationale.
     hostname_id / as_name_id reference the strings interning table
     (created below); -1 / NULL means "no value captured yet". */
  "CREATE TABLE IF NOT EXISTS topo_nodes ("
  "  ip_u32       INTEGER PRIMARY KEY,"
  "  hostname_id  INTEGER,"
  "  asn          INTEGER DEFAULT 0,"
  "  as_name_id   INTEGER,"
  "  country      TEXT,"
  "  role         TEXT,"
  "  path_count   INTEGER DEFAULT 0,"
  "  avg_rtt_ms   REAL,"
  "  last_seen    INTEGER NOT NULL"
  ");"
  "CREATE INDEX IF NOT EXISTS idx_topo_nodes_asn ON topo_nodes(asn);"
  "CREATE TABLE IF NOT EXISTS topo_edges ("
  "  from_u32        INTEGER NOT NULL,"
  "  to_u32          INTEGER NOT NULL,"
  "  asn_boundary    INTEGER DEFAULT 0,"
  "  avg_latency_ms  REAL,"
  "  path_count      INTEGER DEFAULT 0,"
  "  last_seen       INTEGER NOT NULL,"
  "  PRIMARY KEY (from_u32, to_u32)"
  ");"
  /* Reverse-direction lookup: "who points at me?".  The PK covers
     out-edges via its leading column; in-edges need their own index. */
  "CREATE INDEX IF NOT EXISTS idx_topo_edges_to ON topo_edges(to_u32);"
  /* v5d: string interning.  AUTOINCREMENT pins ids monotonically so
     deleted rows do not get their id reused — important when the topo
     nodes table holds a stale reference for a string that was
     accidentally cleared.  UNIQUE on val makes net_db_intern_string
     idempotent via INSERT OR IGNORE + a SELECT lookup. */
  "CREATE TABLE IF NOT EXISTS strings ("
  "  id  INTEGER PRIMARY KEY AUTOINCREMENT,"
  "  val TEXT    NOT NULL UNIQUE"
  ");";

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
    /* COALESCE on every overwrite-style field so a transient probe failure
     * (HTTP timeout, partial banner, TLS handshake error) does not wipe the
     * good data captured by an earlier successful enrichment.  Callers that
     * actually want to clear a field must pass an explicit empty marker
     * value, not NULL.  service/version/cves get the same treatment as
     * web_* because all three suffer the same regression: a banner-grab
     * that times out used to NULL out a perfectly valid Apache 2.4.41
     * detected on the previous run. */
    "  service     = COALESCE(?, service), "
    "  version     = COALESCE(?, version), "
    "  cves        = COALESCE(?, cves), "
    "  web_title   = COALESCE(?, web_title), "
    "  web_server  = COALESCE(?, web_server), "
    "  web_headers = COALESCE(?, web_headers), "
    "  web_paths   = COALESCE(?, web_paths), "
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

  /* Pick rows in either of two states:
   *   (a) never enriched (enriched=0)
   *   (b) enriched in the past, but seen again by a more recent scan
   *       (last_seen > enriched_at)
   *
   * Case (b) is what makes the prev_cves / prev_service / prev_version
   * snapshot infrastructure actually fire.  Before this was added, the
   * gate was `enriched=0` only, so every host was enriched exactly once
   * for life of the DB -- the snapshot columns were declared but never
   * populated, because the trigger condition (a successful UPDATE on a
   * row whose enriched=1) was unreachable.  With (b) added, re-discovery
   * naturally re-enriches a host, and net_db_update_enrichment's CASE
   * WHEN enriched=1 THEN cves ELSE prev_cves END clause finally runs.
   *
   * The enrichment-error cool-down still applies on top: a host whose
   * last enrichment errored stays out of the pool until the retry
   * window elapses, regardless of which leg of the OR picked it. */
  static const char *sql =
    "SELECT DISTINCT ip FROM hosts "
    "WHERE (enriched=0 OR last_seen > enriched_at) "
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
  /* Predicate mirror of net_db_get_unenriched -- see the long comment
   * there for the (enriched=0 OR last_seen > enriched_at) rationale. */
  static const char *sql =
    "SELECT COUNT(*) FROM hosts "
    "WHERE (enriched=0 OR last_seen > enriched_at) "
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
 * Fingerprints — relationship-matching index helpers
 *
 * Each shard owns its own fingerprints table.  Inserts UPSERT on the
 * (ip_u32, kind, value) primary key so re-scans refresh observed_at
 * (and the most-recent port) without creating duplicates.  Look-ups
 * use the inverse index idx_fp_kind_value, which lets the relationship
 * engine resolve "who else carries kind K with value V?" in a single
 * indexed scan even when the table is billions of rows.
 * ----------------------------------------------------------------------- */

int net_db_insert_fingerprint(sqlite3 *db,
                              uint32_t ip_u32, int port,
                              const char *kind, const char *value,
                              int64_t observed_at) {
  if (!db || !kind || !value || !kind[0] || !value[0]) return -1;

  /* UPSERT: on conflict refresh observed_at and the port stamp.
     We use the bound observed_at on the conflict path rather than
     strftime so the caller can stamp a whole batch with one timestamp
     for free, which makes re-scan diffs cluster on the same instant. */
  static const char *sql =
    "INSERT INTO fingerprints (ip_u32, kind, value, port, observed_at) "
    "VALUES (?, ?, ?, ?, ?) "
    "ON CONFLICT(ip_u32, kind, value) DO UPDATE SET "
    "  observed_at = excluded.observed_at, "
    "  port        = excluded.port";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;

  /* ip_u32 stored as int64 — same reason as net_db_update_asn: values
     above INT_MAX (the top half of IPv4) would otherwise round-trip
     through a negative int and break direct numeric comparisons. */
  sqlite3_bind_int64(stmt, 1, static_cast<int64_t>(ip_u32));
  sqlite3_bind_text(stmt, 2, kind, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, value, -1, SQLITE_TRANSIENT);
  if (port > 0) sqlite3_bind_int(stmt, 4, port);
  else          sqlite3_bind_null(stmt, 4);
  sqlite3_bind_int64(stmt, 5, observed_at);

  int rc = sqlite3_step_retry(stmt);
  sqlite3_finalize(stmt);
  return (rc == SQLITE_DONE) ? 0 : -1;
}

std::vector<NetFingerprint>
net_db_find_by_fingerprint(sqlite3 *db,
                           const char *kind, const char *value) {
  std::vector<NetFingerprint> out;
  if (!db || !kind || !value) return out;

  static const char *sql =
    "SELECT ip_u32, port, kind, value, observed_at FROM fingerprints "
    "WHERE kind = ? AND value = ?";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return out;
  sqlite3_bind_text(stmt, 1, kind,  -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, value, -1, SQLITE_TRANSIENT);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    NetFingerprint fp;
    fp.ip_u32      = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
    fp.port        = (sqlite3_column_type(stmt, 1) == SQLITE_NULL)
                       ? 0 : sqlite3_column_int(stmt, 1);
    const unsigned char *k = sqlite3_column_text(stmt, 2);
    const unsigned char *v = sqlite3_column_text(stmt, 3);
    if (k) fp.kind  = reinterpret_cast<const char *>(k);
    if (v) fp.value = reinterpret_cast<const char *>(v);
    fp.observed_at = sqlite3_column_int64(stmt, 4);
    out.push_back(std::move(fp));
  }
  sqlite3_finalize(stmt);
  return out;
}

std::vector<NetFingerprint>
net_db_get_fingerprints_for_ip(sqlite3 *db, const char *ip) {
  std::vector<NetFingerprint> out;
  if (!db || !ip) return out;

  uint32_t ip_u32 = ip_to_u32(ip);
  if (ip_u32 == 0) return out;  /* parse failure */

  static const char *sql =
    "SELECT ip_u32, port, kind, value, observed_at FROM fingerprints "
    "WHERE ip_u32 = ?";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return out;
  sqlite3_bind_int64(stmt, 1, static_cast<int64_t>(ip_u32));

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    NetFingerprint fp;
    fp.ip_u32      = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
    fp.port        = (sqlite3_column_type(stmt, 1) == SQLITE_NULL)
                       ? 0 : sqlite3_column_int(stmt, 1);
    const unsigned char *k = sqlite3_column_text(stmt, 2);
    const unsigned char *v = sqlite3_column_text(stmt, 3);
    if (k) fp.kind  = reinterpret_cast<const char *>(k);
    if (v) fp.value = reinterpret_cast<const char *>(v);
    fp.observed_at = sqlite3_column_int64(stmt, 4);
    out.push_back(std::move(fp));
  }
  sqlite3_finalize(stmt);
  return out;
}

/* -----------------------------------------------------------------------
 * String interning
 *
 * strings(id, val) collapses repeated TEXT values to int IDs.  Storing
 * "CLOUDFLARENET" in a billion topo_nodes rows costs ~13 GB; an int
 * reference is ~8 GB, and the strings table itself adds ~kilobytes
 * because the distinct value set is tiny.  Interning is opt-in — only
 * the topo layer uses it today; hosts.* still uses TEXT for backward
 * compatibility with existing readers.
 * ----------------------------------------------------------------------- */

int64_t net_db_intern_string(sqlite3 *db, const char *val) {
  if (!db || !val || !val[0]) return 0;

  /* Hot path: value already exists.  Try SELECT first to avoid an
     INSERT OR IGNORE no-op (which still bumps AUTOINCREMENT on some
     SQLite versions and wastes ids). */
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, "SELECT id FROM strings WHERE val = ?",
                         -1, &stmt, nullptr) != SQLITE_OK)
    return 0;
  sqlite3_bind_text(stmt, 1, val, -1, SQLITE_TRANSIENT);
  int64_t id = 0;
  if (sqlite3_step(stmt) == SQLITE_ROW)
    id = sqlite3_column_int64(stmt, 0);
  sqlite3_finalize(stmt);
  if (id > 0) return id;

  /* Cold path: insert.  INSERT OR IGNORE so a concurrent inserter
     doesn't crash us; we re-read the id either way. */
  if (sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO strings(val) VALUES(?)",
        -1, &stmt, nullptr) != SQLITE_OK)
    return 0;
  sqlite3_bind_text(stmt, 1, val, -1, SQLITE_TRANSIENT);
  int rc = sqlite3_step_retry(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) return 0;

  /* Detect whether the INSERT actually happened.  This is NOT the same
     as `last_insert_rowid() != 0`: per the SQLite docs, that function
     returns the rowid of the most recent SUCCESSFUL insert on the
     connection, and an ignored INSERT OR IGNORE does NOT change its
     value.  So if a prior insert in this connection succeeded, reading
     last_insert_rowid after a conflict would return that older,
     unrelated rowid and we would mis-attribute an existing string to a
     completely different value.  sqlite3_changes() reports 0 on an
     ignored insert and 1 on a successful one — that is the correct
     gate. */
  if (sqlite3_changes(db) > 0) {
    id = sqlite3_last_insert_rowid(db);
    if (id > 0) return id;
  }

  /* Either the IGNORE branch fired (val already present after the race
     between our SELECT and INSERT) or last_insert_rowid was somehow
     stale — re-SELECT to find the canonical id. */
  if (sqlite3_prepare_v2(db, "SELECT id FROM strings WHERE val = ?",
                         -1, &stmt, nullptr) != SQLITE_OK)
    return 0;
  sqlite3_bind_text(stmt, 1, val, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(stmt) == SQLITE_ROW)
    id = sqlite3_column_int64(stmt, 0);
  sqlite3_finalize(stmt);
  return id;
}

std::string net_db_lookup_string(sqlite3 *db, int64_t id) {
  if (!db || id <= 0) return "";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, "SELECT val FROM strings WHERE id = ?",
                         -1, &stmt, nullptr) != SQLITE_OK)
    return "";
  sqlite3_bind_int64(stmt, 1, id);
  std::string out;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *p = sqlite3_column_text(stmt, 0);
    if (p) out = reinterpret_cast<const char *>(p);
  }
  sqlite3_finalize(stmt);
  return out;
}

/* -----------------------------------------------------------------------
 * Persistent topology — nodes and edges
 *
 * UPSERTs use the same atomic-in-one-statement pattern as the hosts
 * UPSERT above: on first insertion, fields go in directly; on conflict,
 * path_count is bumped, last_seen refreshed, and string fields refresh
 * only when the caller passes a non-empty replacement.  The avg_latency
 * column on edges uses the running-mean update
 *   new_avg = old_avg + (sample - old_avg) / new_count
 * which is stable under order-of-arrival and never accumulates floating-
 * point error the way a sum-of-samples / count division would.
 * ----------------------------------------------------------------------- */

int net_db_upsert_topo_node(sqlite3 *db, const NetTopoNode &node) {
  if (!db) return -1;

  /* Intern the string-valued columns up front so the UPSERT itself
     binds only ints.  Empty -> id 0 -> NULLIF maps to NULL -> COALESCE
     keeps the previously-stored id (no wipe on partial re-observation). */
  int64_t hostname_id = net_db_intern_string(db, node.hostname.c_str());
  int64_t as_name_id  = net_db_intern_string(db, node.as_name.c_str());

  /* path_count is the number of traces that visited this node in the
     in-memory Topology being persisted — a hub router visited by 500
     traces in one tracemap run has node.path_count == 500.  Default to
     1 when the caller leaves it zero (single-observation insert)
     because 0 would make the UPSERT mean "do not increment", which
     would silently lose every re-observation. */
  int64_t batch_count = (node.path_count > 0) ? node.path_count : 1;

  static const char *sql =
    "INSERT INTO topo_nodes "
    "  (ip_u32, hostname_id, asn, as_name_id, country, role, "
    "   path_count, avg_rtt_ms, last_seen) "
    "VALUES (?, NULLIF(?, 0), ?, NULLIF(?, 0), ?, ?, ?, ?, ?) "
    "ON CONFLICT(ip_u32) DO UPDATE SET "
    "  hostname_id = COALESCE(NULLIF(excluded.hostname_id, 0), hostname_id), "
    "  asn         = CASE WHEN excluded.asn  != 0 THEN excluded.asn  ELSE asn  END, "
    "  as_name_id  = COALESCE(NULLIF(excluded.as_name_id, 0), as_name_id), "
    "  country     = COALESCE(NULLIF(excluded.country, ''),  country), "
    "  role        = COALESCE(NULLIF(excluded.role, ''),     role), "
    "  path_count  = path_count + excluded.path_count, "
    "  avg_rtt_ms  = CASE WHEN excluded.avg_rtt_ms IS NOT NULL "
    "                     THEN excluded.avg_rtt_ms ELSE avg_rtt_ms END, "
    "  last_seen   = excluded.last_seen";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;

  sqlite3_bind_int64(stmt, 1, static_cast<int64_t>(node.ip_u32));
  sqlite3_bind_int64(stmt, 2, hostname_id);
  sqlite3_bind_int64(stmt, 3, static_cast<int64_t>(node.asn));
  sqlite3_bind_int64(stmt, 4, as_name_id);
  sqlite3_bind_text (stmt, 5, node.country.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text (stmt, 6, node.role.c_str(),    -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 7, batch_count);
  if (node.avg_rtt_ms > 0.0) sqlite3_bind_double(stmt, 8, node.avg_rtt_ms);
  else                       sqlite3_bind_null  (stmt, 8);
  sqlite3_bind_int64(stmt, 9, node.last_seen);

  int rc = sqlite3_step_retry(stmt);
  sqlite3_finalize(stmt);
  return (rc == SQLITE_DONE) ? 0 : -1;
}

int net_db_upsert_topo_edge(sqlite3 *db, const NetTopoEdge &edge) {
  if (!db) return -1;

  /* Default batch_count to 1 if the caller did not set path_count —
     same reasoning as nodes above: a 0 would freeze the count forever
     under repeated upserts. */
  int64_t batch_count = (edge.path_count > 0) ? edge.path_count : 1;

  /* Running-mean update for BATCHED observations.  excluded.avg_latency_ms
     is the mean of `batch_count` new samples; we merge it with the
     existing path_count-sample mean using the weighted-mean identity:
        new_avg = old_avg + N * (sample - old_avg) / (M + N)
     where M is the prior path_count and N is excluded.path_count.
     This is exact-equivalent to (M * old_avg + N * sample) / (M + N)
     but avoids the multiplication-overflow risk of the sum form on
     large counts.  Skipping the update when the new sample is NULL
     (a `* * *` hop) keeps the stat from being poisoned by zero. */
  static const char *sql =
    "INSERT INTO topo_edges "
    "  (from_u32, to_u32, asn_boundary, avg_latency_ms, path_count, last_seen) "
    "VALUES (?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(from_u32, to_u32) DO UPDATE SET "
    "  asn_boundary   = excluded.asn_boundary, "
    "  avg_latency_ms = CASE WHEN excluded.avg_latency_ms IS NOT NULL "
    "                        THEN COALESCE(avg_latency_ms, 0.0) + "
    "                             excluded.path_count * "
    "                             (excluded.avg_latency_ms - "
    "                              COALESCE(avg_latency_ms, 0.0)) / "
    "                             (path_count + excluded.path_count) "
    "                        ELSE avg_latency_ms END, "
    "  path_count     = path_count + excluded.path_count, "
    "  last_seen      = excluded.last_seen";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;

  sqlite3_bind_int64(stmt, 1, static_cast<int64_t>(edge.from_u32));
  sqlite3_bind_int64(stmt, 2, static_cast<int64_t>(edge.to_u32));
  sqlite3_bind_int  (stmt, 3, edge.asn_boundary ? 1 : 0);
  if (edge.avg_latency_ms > 0.0)
    sqlite3_bind_double(stmt, 4, edge.avg_latency_ms);
  else
    sqlite3_bind_null  (stmt, 4);
  sqlite3_bind_int64(stmt, 5, batch_count);
  sqlite3_bind_int64(stmt, 6, edge.last_seen);

  int rc = sqlite3_step_retry(stmt);
  sqlite3_finalize(stmt);
  return (rc == SQLITE_DONE) ? 0 : -1;
}

static std::vector<NetTopoEdge>
edge_rows(sqlite3 *db, const char *sql, uint32_t bind_u32) {
  std::vector<NetTopoEdge> out;
  if (!db) return out;
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return out;
  sqlite3_bind_int64(stmt, 1, static_cast<int64_t>(bind_u32));
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    NetTopoEdge e;
    e.from_u32       = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
    e.to_u32         = static_cast<uint32_t>(sqlite3_column_int64(stmt, 1));
    e.asn_boundary   = sqlite3_column_int(stmt, 2);
    e.avg_latency_ms = (sqlite3_column_type(stmt, 3) == SQLITE_NULL)
                         ? 0.0 : sqlite3_column_double(stmt, 3);
    e.path_count     = sqlite3_column_int(stmt, 4);
    e.last_seen      = sqlite3_column_int64(stmt, 5);
    out.push_back(std::move(e));
  }
  sqlite3_finalize(stmt);
  return out;
}

std::vector<NetTopoEdge>
net_db_get_topo_edges_from(sqlite3 *db, uint32_t from_u32) {
  return edge_rows(db,
    "SELECT from_u32, to_u32, asn_boundary, avg_latency_ms, "
    "path_count, last_seen FROM topo_edges WHERE from_u32 = ?",
    from_u32);
}

std::vector<NetTopoEdge>
net_db_get_topo_edges_to(sqlite3 *db, uint32_t to_u32) {
  return edge_rows(db,
    "SELECT from_u32, to_u32, asn_boundary, avg_latency_ms, "
    "path_count, last_seen FROM topo_edges WHERE to_u32 = ?",
    to_u32);
}

bool net_db_get_topo_node(sqlite3 *db, uint32_t ip_u32, NetTopoNode *out) {
  if (!db || !out) return false;
  static const char *sql =
    "SELECT n.ip_u32, "
    "       COALESCE(h.val, ''), "
    "       n.asn, "
    "       COALESCE(a.val, ''), "
    "       COALESCE(n.country, ''), "
    "       COALESCE(n.role, ''), "
    "       n.path_count, "
    "       COALESCE(n.avg_rtt_ms, 0.0), "
    "       n.last_seen "
    "FROM topo_nodes n "
    "LEFT JOIN strings h ON h.id = n.hostname_id "
    "LEFT JOIN strings a ON a.id = n.as_name_id "
    "WHERE n.ip_u32 = ?";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int64(stmt, 1, static_cast<int64_t>(ip_u32));

  bool found = false;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    out->ip_u32     = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
    const unsigned char *h = sqlite3_column_text(stmt, 1);
    out->hostname   = h ? reinterpret_cast<const char *>(h) : "";
    out->asn        = static_cast<uint32_t>(sqlite3_column_int64(stmt, 2));
    const unsigned char *a = sqlite3_column_text(stmt, 3);
    out->as_name    = a ? reinterpret_cast<const char *>(a) : "";
    const unsigned char *c = sqlite3_column_text(stmt, 4);
    out->country    = c ? reinterpret_cast<const char *>(c) : "";
    const unsigned char *r = sqlite3_column_text(stmt, 5);
    out->role       = r ? reinterpret_cast<const char *>(r) : "";
    out->path_count = sqlite3_column_int(stmt, 6);
    out->avg_rtt_ms = sqlite3_column_double(stmt, 7);
    out->last_seen  = sqlite3_column_int64(stmt, 8);
    found = true;
  }
  sqlite3_finalize(stmt);
  return found;
}

int64_t net_db_count_topo_nodes(sqlite3 *db) {
  if (!db) return -1;
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM topo_nodes",
                         -1, &stmt, nullptr) != SQLITE_OK)
    return -1;
  int64_t c = 0;
  if (sqlite3_step(stmt) == SQLITE_ROW) c = sqlite3_column_int64(stmt, 0);
  sqlite3_finalize(stmt);
  return c;
}

int64_t net_db_count_topo_edges(sqlite3 *db) {
  if (!db) return -1;
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM topo_edges",
                         -1, &stmt, nullptr) != SQLITE_OK)
    return -1;
  int64_t c = 0;
  if (sqlite3_step(stmt) == SQLITE_ROW) c = sqlite3_column_int64(stmt, 0);
  sqlite3_finalize(stmt);
  return c;
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

/* Find the matching '}' that closes the JSON object starting at `start`
 * (which must point at '{').  State machine: tracks brace depth while
 * skipping over JSON string literals, honoring backslash escapes inside
 * strings.  Needed because net_enrich's json_escape does NOT escape '{'
 * or '}' (JSON spec does not require it), so a literal '}' inside a CVE
 * description used to defeat the previous find('}') here -- it landed
 * on the description's '}' instead of the object terminator, then the
 * "id":" search inside the truncated substring missed the id and the
 * entry was silently dropped.  Returns npos if the input is malformed. */
static size_t db_json_find_object_end(const std::string &json, size_t start) {
  if (start >= json.size() || json[start] != '{') return std::string::npos;
  int  depth        = 0;
  bool in_string    = false;
  bool escape_next  = false;
  for (size_t i = start; i < json.size(); i++) {
    char c = json[i];
    if (escape_next) { escape_next = false; continue; }
    if (in_string) {
      if (c == '\\')      escape_next = true;
      else if (c == '"')  in_string = false;
      continue;
    }
    if (c == '"')       in_string = true;
    else if (c == '{')  depth++;
    else if (c == '}') {
      depth--;
      if (depth == 0) return i;
    }
  }
  return std::string::npos;
}

std::vector<std::string> net_db_parse_cve_ids(const std::string &cves_json) {
  std::vector<std::string> ids;
  if (cves_json.empty() || cves_json == "[]") return ids;

  size_t pos = 0;
  while (pos < cves_json.size()) {
    /* Find next object opener.  The '{' we want is always at the start
       of an array element; '{' inside a quoted string is skipped over
       by db_json_find_object_end below, so this find() only ever lands
       on a real opener. */
    size_t obj_start = cves_json.find('{', pos);
    if (obj_start == std::string::npos) break;

    /* Find the matching '}'.  Use the string-aware finder so a '}' inside
       a description (CVE prose contains braces in code snippets, regex
       examples, set-builder notation) does not truncate the object and
       drop the entry from the parse. */
    size_t obj_end = db_json_find_object_end(cves_json, obj_start);
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
