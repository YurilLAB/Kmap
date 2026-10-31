/* Completed watchlist snapshots + real SQLite, entirely offline. */
#include "watchlist_state.h"
#include <cstdio>
#include <cstdlib>

static int checks = 0, failures = 0;
#define CHECK(value) do { ++checks; if (!(value)) { ++failures; \
  std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #value); } } while (0)

static void sql(sqlite3 *db, const char *text) {
  if (sqlite3_exec(db, text, nullptr, nullptr, nullptr) != SQLITE_OK) {
    std::fprintf(stderr, "fixture SQL failed: %s\n", sqlite3_errmsg(db));
    std::exit(2);
  }
}
static int64_t scalar(sqlite3 *db, const char *text) {
  sqlite3_stmt *statement = nullptr;
  CHECK(sqlite3_prepare_v2(db, text, -1, &statement, nullptr) == SQLITE_OK);
  if (!statement) return -1;
  CHECK(sqlite3_step(statement) == SQLITE_ROW);
  const int64_t value = sqlite3_column_int64(statement, 0);
  CHECK(sqlite3_finalize(statement) == SQLITE_OK);
  return value;
}
static void snapshot(sqlite3 *db, int count, int64_t time) {
  NetWatchlistState state;
  CHECK(net_watchlist_state_open(db, state));
  CHECK(state.has_snapshot);
  CHECK(state.has_attributes);
  CHECK(state.previous_scan_time == time);
  CHECK(scalar(db, "SELECT count(*) FROM watchlist_open") == count);
  CHECK(scalar(db, "SELECT count(*) FROM watchlist_baseline") == count);
  CHECK(sqlite3_get_autocommit(db));
  CHECK(sqlite3_next_stmt(db, nullptr) == nullptr);
}
static void close_db(sqlite3 *db) {
  CHECK(sqlite3_next_stmt(db, nullptr) == nullptr);
  CHECK(sqlite3_get_autocommit(db));
  CHECK(sqlite3_close(db) == SQLITE_OK);
}

int main() {
  constexpr uint32_t ip = 0x7f000001;
  const std::vector<std::pair<uint32_t, int>> a{{ip, 80}}, both{{ip, 80}, {ip, 81}};
  sqlite3 *db = net_db_open(":memory:");
  CHECK(db != nullptr);
  if (!db) return 2;
  NetWatchlistState initial;
  CHECK(net_watchlist_state_open(db, initial));
  CHECK(!initial.has_snapshot && initial.previous_scan_time == 0);
  CHECK(net_db_insert_host(db, ip, 80, "tcp", 10) == 1);
  CHECK(net_db_insert_host(db, ip, 81, "tcp", 10) == 1);
  CHECK(net_watchlist_state_save(db, both, 100));
  snapshot(db, 2, 100);
  // Same-second closure, repeated completion, duplicate input and empty set
  // must not reintroduce historical rows through timestamp comparisons.
  CHECK(net_watchlist_state_save(db, a, 100));
  snapshot(db, 1, 100);
  CHECK(net_watchlist_state_save(db, {{ip, 80}, {ip, 80}}, 100));
  snapshot(db, 1, 100);
  CHECK(scalar(db, "SELECT count(*) FROM hosts") == 2);
  CHECK(scalar(db, "SELECT min(first_seen) FROM hosts") == 10);
  CHECK(net_watchlist_state_save(db, {}, 100));
  snapshot(db, 0, 100);
  CHECK(net_watchlist_state_save(db, a, 101));

  CHECK(!net_watchlist_state_save(db, {{ip, 0}}, 102));
  snapshot(db, 1, 101);
  CHECK(scalar(db, "SELECT port FROM watchlist_open") == 80);
  for (const char *failure : {"ABORT", "ROLLBACK"}) {
    const std::string trigger = "CREATE TRIGGER reject_second BEFORE INSERT ON watchlist_open "
      "WHEN NEW.port=81 BEGIN SELECT RAISE(" + std::string(failure) + ", 'fixture'); END";
    sql(db, trigger.c_str());
    CHECK(!net_watchlist_state_save(db, both, 102));
    snapshot(db, 1, 101);
    sql(db, "DROP TRIGGER reject_second");
  }
  sqlite3_commit_hook(db, [](void *) { return 1; }, nullptr);
  CHECK(!net_watchlist_state_save(db, both, 102));
  sqlite3_commit_hook(db, nullptr, nullptr);
  snapshot(db, 1, 101);
  sql(db, "PRAGMA query_only=ON");
  CHECK(!net_watchlist_state_save(db, both, 102));
  sql(db, "PRAGMA query_only=OFF");
  snapshot(db, 1, 101);
  CHECK(net_db_begin(db) == 0);
  CHECK(!net_watchlist_state_save(db, both, 102));
  CHECK(!sqlite3_get_autocommit(db)); // Never rolls back a caller-owned transaction.
  CHECK(net_db_rollback(db) == 0);
  snapshot(db, 1, 101);
  CHECK(net_watchlist_state_save(db, both, 102));
  snapshot(db, 2, 102);
  close_db(db);

  // Collection keeps the latest attributes even if publication fails. Only a
  // completed snapshot advances the comparison values; NULL metadata becomes
  // empty text, without changing the current hosts row.
  db = net_db_open(":memory:");
  CHECK(net_watchlist_state_open(db, initial));
  CHECK(net_db_insert_host(db, ip, 80, "tcp", 10) == 1);
  CHECK(net_watchlist_state_save(db, a, 1));
  CHECK(scalar(db, "SELECT service='' AND version='' AND cves='' AND web_title='' FROM watchlist_baseline") == 1);
  sql(db, "UPDATE hosts SET service='http',version='v1',web_title='old'");
  CHECK(net_watchlist_state_save(db, a, 2));
  sql(db, "UPDATE hosts SET version='v2',web_title='new'");
  for (const char *failure : {"ABORT", "ROLLBACK"}) {
    const std::string trigger = "CREATE TRIGGER reject_attributes BEFORE INSERT ON watchlist_baseline "
      "BEGIN SELECT RAISE(" + std::string(failure) + ", 'fixture'); END";
    sql(db, trigger.c_str());
    CHECK(!net_watchlist_state_save(db, a, 3));
    snapshot(db, 1, 2);
    CHECK(scalar(db, "SELECT version='v1' AND web_title='old' FROM watchlist_baseline") == 1);
    CHECK(scalar(db, "SELECT version='v2' AND web_title='new' FROM hosts") == 1);
    sql(db, "DROP TRIGGER reject_attributes");
  }
  CHECK(net_watchlist_state_save(db, a, 3));
  CHECK(scalar(db, "SELECT version='v2' AND web_title='new' FROM watchlist_baseline") == 1);
  CHECK(net_watchlist_state_save(db, {}, 4));
  snapshot(db, 0, 4);
  // Missing collected rows must not silently create a partial baseline.
  CHECK(!net_watchlist_state_save(db, {{ip, 81}}, 5));
  snapshot(db, 0, 4);
  close_db(db);

  // An older membership-only snapshot gets an explicit attributes baseline
  // after its first successful completion; no existing host data is erased.
  db = net_db_open(":memory:");
  CHECK(net_db_insert_host(db, ip, 80, "tcp", 10) == 1);
  sql(db, "CREATE TABLE scan_meta(key TEXT PRIMARY KEY,value INTEGER);"
          "INSERT INTO scan_meta VALUES('last_scan_ts',123),('open_snapshot_ready',1);"
          "CREATE TABLE watchlist_open(ip TEXT,port INTEGER,PRIMARY KEY(ip,port));"
          "INSERT INTO watchlist_open VALUES('127.0.0.1',80)");
  CHECK(net_watchlist_state_open(db, initial));
  CHECK(initial.has_snapshot && !initial.has_attributes && initial.previous_scan_time == 123);
  CHECK(net_watchlist_state_save(db, a, 124));
  snapshot(db, 1, 124);
  CHECK(scalar(db, "SELECT count(*) FROM hosts") == 1);
  close_db(db);

  // Legacy metadata remains available until a first complete snapshot exists.
  db = net_db_open(":memory:");
  sql(db, "CREATE TABLE scan_meta(key TEXT PRIMARY KEY,value INTEGER);"
          "INSERT INTO scan_meta VALUES('last_scan_ts',123)");
  CHECK(net_watchlist_state_open(db, initial));
  CHECK(!initial.has_snapshot && initial.previous_scan_time == 123);
  CHECK(net_watchlist_state_save(db, {}, 123));
  snapshot(db, 0, 123);
  close_db(db);
  db = net_db_open(":memory:");
  sql(db, "CREATE TABLE scan_meta(wrong_column INTEGER)");
  CHECK(!net_watchlist_state_open(db, initial));
  close_db(db);
  std::printf("watchlist snapshots: checks=%d failures=%d\n", checks, failures);
  return failures ? 1 : 0;
}
