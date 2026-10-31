/* Completed watchlist membership, independent of enrichment timestamps. */
#ifndef KMAP_WATCHLIST_STATE_H
#define KMAP_WATCHLIST_STATE_H

#include "net_db.h"
#include <utility>
#include <vector>

struct NetWatchlistState {
  bool has_snapshot = false;
  bool has_attributes = false;
  int64_t previous_scan_time = 0;
};

inline bool net_watchlist_state_open(sqlite3 *db, NetWatchlistState &state) {
  if (sqlite3_exec(db,
      "CREATE TABLE IF NOT EXISTS scan_meta (key TEXT PRIMARY KEY, value INTEGER);"
      "CREATE TABLE IF NOT EXISTS watchlist_open ("
      "ip TEXT NOT NULL, port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),"
      "PRIMARY KEY(ip,port));"
      "CREATE TABLE IF NOT EXISTS watchlist_baseline ("
      "ip TEXT NOT NULL,port INTEGER NOT NULL,service TEXT NOT NULL,version TEXT NOT NULL,"
      "cves TEXT NOT NULL,web_title TEXT NOT NULL,PRIMARY KEY(ip,port))",
      nullptr, nullptr, nullptr) != SQLITE_OK) return false;
  sqlite3_stmt *statement = nullptr;
  if (sqlite3_prepare_v2(db,
      "SELECT key,value FROM scan_meta WHERE key IN ('last_scan_ts','open_snapshot_ready','attributes_snapshot_ready')",
      -1, &statement, nullptr) != SQLITE_OK) return false;
  state = {};
  int status;
  while ((status = sqlite3_step(statement)) == SQLITE_ROW) {
    const char *key = reinterpret_cast<const char *>(sqlite3_column_text(statement, 0));
    if (!key) continue;
    if (std::string(key) == "last_scan_ts") state.previous_scan_time = sqlite3_column_int64(statement, 1);
    if (std::string(key) == "open_snapshot_ready") state.has_snapshot = sqlite3_column_int(statement, 1) == 1;
    if (std::string(key) == "attributes_snapshot_ready") state.has_attributes = sqlite3_column_int(statement, 1) == 1;
  }
  const int finalized = sqlite3_finalize(statement);
  return status == SQLITE_DONE && finalized == SQLITE_OK;
}

// Call only after a completed run's reports have been written successfully.
// A failed update preserves the previous complete membership and metadata.
inline bool net_watchlist_state_save(sqlite3 *db,
    const std::vector<std::pair<uint32_t, int>> &opens, int64_t scan_time) {
  if (net_db_begin(db) != 0) return false;
  auto fail = [&]() { net_db_rollback(db); return false; };
  if (sqlite3_exec(db, "DELETE FROM watchlist_open", nullptr, nullptr, nullptr) != SQLITE_OK)
    return fail();
  sqlite3_stmt *statement = nullptr;
  if (sqlite3_prepare_v2(db, "INSERT INTO watchlist_open(ip,port) VALUES(?,?) ON CONFLICT(ip,port) DO NOTHING",
      -1, &statement, nullptr) != SQLITE_OK) return fail();
  bool valid = true;
  for (const auto &entry : opens) {
    const std::string ip = u32_to_ip(entry.first);
    int status = sqlite3_bind_text(statement, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
    if (status == SQLITE_OK) status = sqlite3_bind_int(statement, 2, entry.second);
    if (status == SQLITE_OK) status = sqlite3_step(statement);
    if (status != SQLITE_DONE || sqlite3_reset(statement) != SQLITE_OK) { valid = false; break; }
  }
  if (sqlite3_finalize(statement) != SQLITE_OK) valid = false;
  if (!valid) return fail();
  // Retain the completed comparison values separately from current collection.
  // Failed reports can leave newer hosts rows, which must remain available,
  // without consuming the service/version change on the next retry. A missing
  // host fails the NOT NULL constraint rather than saving an incomplete set.
  if (sqlite3_exec(db,
      "DELETE FROM watchlist_baseline;"
      "INSERT INTO watchlist_baseline(ip,port,service,version,cves,web_title) "
      "SELECT h.ip,h.port,COALESCE(h.service,''),COALESCE(h.version,''),"
      "COALESCE(h.cves,''),COALESCE(h.web_title,'') FROM watchlist_open w "
      "LEFT JOIN hosts h ON h.ip=w.ip AND h.port=w.port",
      nullptr, nullptr, nullptr) != SQLITE_OK) return fail();
  statement = nullptr;
  if (sqlite3_prepare_v2(db,
      "INSERT OR REPLACE INTO scan_meta(key,value) VALUES('last_scan_ts',?),"
      "('open_snapshot_ready',1),('attributes_snapshot_ready',1)",
      -1, &statement, nullptr) != SQLITE_OK) return fail();
  int status = sqlite3_bind_int64(statement, 1, scan_time);
  if (status == SQLITE_OK) status = sqlite3_step(statement);
  const int finalized = sqlite3_finalize(statement);
  if (status != SQLITE_DONE || finalized != SQLITE_OK) return fail();
  if (net_db_commit(db) != 0) return fail();
  return true;
}

#endif
