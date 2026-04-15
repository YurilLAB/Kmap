/*
 * net_db.cc -- Sharded SQLite database manager for Kmap net-scan.
 */

#ifdef WIN32
#include "kmap_winconfig.h"
#endif

#include "net_db.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

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
  "  ip            TEXT NOT NULL,"
  "  port          INTEGER NOT NULL,"
  "  proto         TEXT DEFAULT 'tcp',"
  "  first_seen    INTEGER NOT NULL,"
  "  last_seen     INTEGER NOT NULL,"
  "  service       TEXT,"
  "  version       TEXT,"
  "  cves          TEXT,"
  "  web_title     TEXT,"
  "  web_server    TEXT,"
  "  web_headers   TEXT,"
  "  web_paths     TEXT,"
  "  asn           INTEGER DEFAULT 0,"
  "  as_name       TEXT,"
  "  country       TEXT,"
  "  bgp_prefix    TEXT,"
  "  enriched      INTEGER DEFAULT 0,"
  "  PRIMARY KEY (ip, port)"
  ");"
  "CREATE INDEX IF NOT EXISTS idx_hosts_port     ON hosts(port);"
  "CREATE INDEX IF NOT EXISTS idx_hosts_service  ON hosts(service);"
  "CREATE INDEX IF NOT EXISTS idx_hosts_enriched ON hosts(enriched);"
  "CREATE INDEX IF NOT EXISTS idx_hosts_lastseen ON hosts(last_seen);"
  "CREATE INDEX IF NOT EXISTS idx_hosts_asn      ON hosts(asn);"
  "CREATE INDEX IF NOT EXISTS idx_hosts_country  ON hosts(country);";

/* Migration SQL — adds ASN columns to existing databases */
static const char *MIGRATE_ASN_SQL =
  "ALTER TABLE hosts ADD COLUMN asn INTEGER DEFAULT 0;"
  "ALTER TABLE hosts ADD COLUMN as_name TEXT;"
  "ALTER TABLE hosts ADD COLUMN country TEXT;"
  "ALTER TABLE hosts ADD COLUMN bgp_prefix TEXT;";

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

  /* Migrate existing databases: add ASN columns if missing.
   * ALTER TABLE ADD COLUMN is a no-op if the column already exists
   * in SQLite >= 3.35, but older versions return an error — ignore it. */
  sqlite3_exec(db, MIGRATE_ASN_SQL, nullptr, nullptr, nullptr);
  /* Create ASN indexes (safe to call repeatedly) */
  sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_hosts_asn ON hosts(asn)",
               nullptr, nullptr, nullptr);
  sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_hosts_country ON hosts(country)",
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

  static const char *sql =
    "INSERT OR IGNORE INTO hosts (ip, port, proto, first_seen, last_seen) "
    "VALUES (?, ?, ?, ?, ?)";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;

  std::string ip_str = u32_to_ip(ip);
  sqlite3_bind_text(stmt, 1, ip_str.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 2, port);
  sqlite3_bind_text(stmt, 3, proto, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 4, timestamp);
  sqlite3_bind_int64(stmt, 5, timestamp);

  int rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc == SQLITE_DONE) {
    /* Check if row was actually inserted (not a duplicate) */
    return sqlite3_changes(db) > 0 ? 1 : 0;
  }
  return -1;
}

int net_db_update_enrichment(sqlite3 *db, const char *ip, int port,
                             const char *service, const char *version,
                             const char *cves_json,
                             const char *web_title, const char *web_server,
                             const char *web_headers, const char *web_paths) {
  if (!db) return -1;

  static const char *sql =
    "UPDATE hosts SET service=?, version=?, cves=?, web_title=?, "
    "web_server=?, web_headers=?, web_paths=?, enriched=1, "
    "last_seen=strftime('%s','now') "
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

  bind_or_null(1, service);
  bind_or_null(2, version);
  bind_or_null(3, cves_json);
  bind_or_null(4, web_title);
  bind_or_null(5, web_server);
  bind_or_null(6, web_headers);
  bind_or_null(7, web_paths);
  sqlite3_bind_text(stmt, 8, ip, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 9, port);

  int rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  return (rc == SQLITE_DONE) ? 0 : -1;
}

int net_db_update_asn(sqlite3 *db, const char *ip,
                      uint32_t asn, const char *as_name,
                      const char *country, const char *bgp_prefix) {
  if (!db || !ip) return -1;

  static const char *sql =
    "UPDATE hosts SET asn=?, as_name=?, country=?, bgp_prefix=? "
    "WHERE ip=?";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return -1;

  sqlite3_bind_int(stmt, 1, static_cast<int>(asn));
  auto bind_or_null = [&](int idx, const char *val) {
    if (val && val[0])
      sqlite3_bind_text(stmt, idx, val, -1, SQLITE_TRANSIENT);
    else
      sqlite3_bind_null(stmt, idx);
  };
  bind_or_null(2, as_name);
  bind_or_null(3, country);
  bind_or_null(4, bgp_prefix);
  sqlite3_bind_text(stmt, 5, ip, -1, SQLITE_TRANSIENT);

  int rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  return (rc == SQLITE_DONE) ? 0 : -1;
}

std::vector<std::string> net_db_get_unenriched(sqlite3 *db, int limit) {
  std::vector<std::string> ips;
  if (!db) return ips;

  static const char *sql =
    "SELECT DISTINCT ip FROM hosts WHERE enriched=0 LIMIT ?";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return ips;

  sqlite3_bind_int(stmt, 1, limit);

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

  static const char *sql =
    "SELECT ip, port, proto, first_seen, last_seen, service, version, "
    "cves, web_title, web_server, web_headers, web_paths, "
    "asn, as_name, country, bgp_prefix, enriched "
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
    h.asn         = static_cast<uint32_t>(sqlite3_column_int(stmt, 12));
    h.as_name     = col(13);
    h.country     = col(14);
    h.bgp_prefix  = col(15);
    h.enriched    = sqlite3_column_int(stmt, 16);
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

int64_t net_db_count_unenriched(sqlite3 *db) {
  if (!db) return -1;
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM hosts WHERE enriched=0",
                         -1, &stmt, nullptr) != SQLITE_OK)
    return -1;
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
