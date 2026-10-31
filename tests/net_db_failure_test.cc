/* Real SQLite failure/recovery fixtures. No sockets or scanner execution. */
#include "net_db.h"
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <random>
#include <string>
#include <vector>

static int failures = 0;
#define CHECK(x) do { if (!(x)) { ++failures; \
  std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); } } while (0)
static void sql(sqlite3 *db, const std::string &s) {
  int rc = sqlite3_exec(db, s.c_str(), nullptr, nullptr, nullptr);
  if (rc != SQLITE_OK) {
    std::fprintf(stderr, "fixture SQL failed: %s: %s\n", s.c_str(), sqlite3_errmsg(db));
    std::exit(2);
  }
}
static int64_t scalar(sqlite3 *db, const char *s) {
  sqlite3_stmt *st = nullptr;
  CHECK(sqlite3_prepare_v2(db, s, -1, &st, nullptr) == SQLITE_OK);
  if (!st) return -999;
  CHECK(sqlite3_step(st) == SQLITE_ROW);
  int64_t value = sqlite3_column_int64(st, 0);
  CHECK(sqlite3_finalize(st) == SQLITE_OK);
  return value;
}
static void close_db(sqlite3 *db) {
  CHECK(sqlite3_next_stmt(db, nullptr) == nullptr);
  CHECK(sqlite3_close(db) == SQLITE_OK);
}
struct Fixture {
  std::filesystem::path dir;
  Fixture() {
    std::random_device rng;
    for (int attempt = 0; attempt < 20; ++attempt) {
      auto candidate = std::filesystem::temp_directory_path() /
          ("kmap-db-failure-" + std::to_string(rng()));
      if (std::filesystem::create_directory(candidate)) {
        dir = candidate;
        std::printf("fixture_dir=%s\n", dir.string().c_str());
        return;
      }
    }
    std::exit(2);
  }
  std::string path(const char *name) { return (dir / name).string(); }
  ~Fixture() {
    if (failures) {
      std::fprintf(stderr, "Retaining failed storage fixture: %s\n", dir.string().c_str());
      return;
    }
    // Only remove direct files created in this exclusively owned directory.
    std::error_code ec;
    for (const auto &entry : std::filesystem::directory_iterator(dir, ec))
      if (entry.is_regular_file()) std::filesystem::remove(entry.path(), ec);
    std::filesystem::remove(dir, ec);
  }
};
static std::vector<NetDbOpen> records(size_t count) {
  std::vector<NetDbOpen> out;
  for (size_t i = 0; i < count; ++i)
    out.push_back({static_cast<uint32_t>(0xc0000201 + i), 80, 10});
  return out;
}
static void constraint_failure(bool outer) {
  sqlite3 *db = net_db_open(":memory:"); CHECK(db); if (!db) return;
  CHECK(net_db_insert_host(db, 1, 443, "tcp", 1) == 1);
  CHECK(net_db_insert_host(db, 0xc0000201u, 80, "tcp", 1) == 1);
  if (outer) {
    sql(db, "BEGIN");
    // Work before the bulk savepoint must survive an ordinary row failure.
    CHECK(net_db_insert_host(db, 2, 443, "tcp", 1) == 1);
  }
  int expected_before = outer ? 3 : 2;
  sql(db, "CREATE TEMP TRIGGER reject_middle BEFORE INSERT ON hosts "
          "WHEN NEW.ip='192.0.2.2' BEGIN SELECT RAISE(ABORT,'fixture reject'); END");
  auto rows = records(3);
  int result = net_db_insert_opens_bulk(db, rows.data(), rows.size());
  int64_t actual = net_db_count(db);
  std::printf("constraint outer=%d result=%d rows=%lld expected=-1,%d\n",
              outer, result, static_cast<long long>(actual), expected_before);
  CHECK(result == -1); CHECK(actual == expected_before);
  auto unchanged = net_db_get_host(db, "192.0.2.1");
  CHECK(unchanged.size() == 1);
  if (!unchanged.empty()) {
    CHECK(unchanged[0].scan_count == 1);
    CHECK(unchanged[0].first_seen == 1 && unchanged[0].last_seen == 1);
  }
  CHECK(sqlite3_get_autocommit(db) == !outer);
  sql(db, "DROP TRIGGER reject_middle");
  CHECK(net_db_insert_opens_bulk(db, rows.data(), rows.size()) == 3);
  if (outer) sql(db, "COMMIT");
  CHECK(net_db_count(db) == expected_before + 2);
  close_db(db);
}
static void full_failure(Fixture &fixture) {
  auto path = fixture.path("full.db");
  sqlite3 *db = net_db_open(path); CHECK(db); if (!db) return;
  CHECK(net_db_insert_host(db, 1, 443, "tcp", 1) == 1);
  int64_t pages = scalar(db, "PRAGMA page_count");
  sql(db, "PRAGMA max_page_count=" + std::to_string(pages));
  sql(db, "BEGIN");
  auto rows = records(512);
  int result = net_db_insert_opens_bulk(db, rows.data(), rows.size());
  int64_t actual = net_db_count(db);
  std::printf("full result=%d rows=%lld autocommit=%d expected=-1,1\n",
              result, static_cast<long long>(actual), sqlite3_get_autocommit(db));
  CHECK(result == -1); CHECK(actual == 1);
  if (!sqlite3_get_autocommit(db)) sql(db, "ROLLBACK");
  close_db(db);
  db = net_db_open(path); CHECK(db); if (!db) return;
  CHECK(net_db_count(db) == 1);
  sql(db, "PRAGMA max_page_count=10000");
  CHECK(net_db_insert_opens_bulk(db, rows.data(), rows.size()) == 512);
  CHECK(net_db_count(db) == 513);
  close_db(db);
}
static void readonly_and_lock(Fixture &fixture) {
  auto path = fixture.path("locking.db");
  sqlite3 *db = net_db_open(path); CHECK(db); if (!db) return;
  CHECK(net_db_insert_host(db, 1, 443, "tcp", 1) == 1);
  close_db(db);
  CHECK(sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
  auto rows = records(1);
  int result = net_db_insert_opens_bulk(db, rows.data(), 1);
  std::printf("readonly result=%d expected=-1\n", result);
  CHECK(result == -1); CHECK(net_db_count(db) == 1); close_db(db);
  db = net_db_open(path);
  sqlite3 *other = net_db_open(path); CHECK(db && other);
  if (!db || !other) std::exit(2);
  sqlite3_busy_timeout(db, 0); sqlite3_busy_timeout(other, 0);
  sql(db, "BEGIN IMMEDIATE");
  result = net_db_insert_opens_bulk(other, rows.data(), 1);
  std::printf("locked result=%d expected=-1\n", result);
  CHECK(result == -1); CHECK(net_db_count(other) == 1);
  sql(db, "ROLLBACK");
  CHECK(net_db_insert_opens_bulk(other, rows.data(), 1) == 1);
  close_db(other); close_db(db);
}
static void locked_counts(Fixture &fixture) {
  auto path = fixture.path("count-lock.db");
  sqlite3 *db = net_db_open(path); CHECK(db); if (!db) return;
  CHECK(net_db_insert_host(db, 1, 80, "tcp", 1) == 1);
  sql(db, "PRAGMA journal_mode=DELETE");
  sqlite3 *writer = nullptr;
  CHECK(sqlite3_open(path.c_str(), &writer) == SQLITE_OK);
  sqlite3_busy_timeout(db, 0);
  sql(writer, "BEGIN EXCLUSIVE");
  using Count = int64_t (*)(sqlite3 *);
  Count functions[] = {net_db_count, net_db_count_topo_nodes, net_db_count_topo_edges};
  for (auto count : functions) {
    int64_t result = count(db);
    std::printf("locked count=%lld expected=-1\n", static_cast<long long>(result));
    CHECK(result == -1);
  }
  CHECK(net_db_count_unenriched(db) == -1);
  sql(writer, "ROLLBACK"); close_db(writer);
  CHECK(net_db_count(db) == 1); CHECK(net_db_count_unenriched(db) == 1);
  close_db(db);
}
static int interrupt_once(void *context) {
  bool &fired = *static_cast<bool *>(context);
  if (fired) return 0;
  fired = true;
  return 1;
}
static void interrupted_transaction() {
  sqlite3 *db = net_db_open(":memory:"); CHECK(db); if (!db) return;
  CHECK(net_db_insert_host(db, 1, 80, "tcp", 1) == 1);
  sql(db, "CREATE TEMP TRIGGER slow_middle BEFORE INSERT ON hosts "
          "WHEN NEW.ip='192.0.2.2' BEGIN "
          "SELECT sum(n) FROM (WITH RECURSIVE numbers(n) AS "
          "(VALUES(1) UNION ALL SELECT n+1 FROM numbers WHERE n<10000) "
          "SELECT n FROM numbers); END");
  auto rows = records(3);
  sql(db, "BEGIN");
  bool fired = false;
  sqlite3_progress_handler(db, 1000, interrupt_once, &fired);
  int result = net_db_insert_opens_bulk(db, rows.data(), rows.size());
  sqlite3_progress_handler(db, 0, nullptr, nullptr);
  std::printf("interrupted bulk result=%d rows=%lld expected=-1,1\n", result,
              static_cast<long long>(net_db_count(db)));
  CHECK(fired); CHECK(result == -1); CHECK(net_db_count(db) == 1);
  CHECK(sqlite3_get_autocommit(db));
  sql(db, "DROP TRIGGER slow_middle");
  CHECK(net_db_insert_opens_bulk(db, rows.data(), rows.size()) == 3);
  CHECK(net_db_count(db) == 4);
  close_db(db);
}

int main() {
  Fixture fixture;
  constraint_failure(false); constraint_failure(true);
  full_failure(fixture); readonly_and_lock(fixture); locked_counts(fixture);
  interrupted_transaction();
  std::printf("storage failures: %d failed assertions\n", failures);
  return failures ? 1 : 0;
}
