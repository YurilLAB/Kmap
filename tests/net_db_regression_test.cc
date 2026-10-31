/* Offline regressions for input validation, schema upgrades and missing
 * topology measurements. Links the real net_db.cc and bundled SQLite. */
#include "../net_db.h"
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <random>
#include <stdexcept>
#include <string>

static int failures = 0;
#define CHECK(expr) do { if (!(expr)) { \
  std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
  ++failures; } } while (0)

static void sql(sqlite3 *db, const char *statement) {
  char *error = nullptr;
  int rc = sqlite3_exec(db, statement, nullptr, nullptr, &error);
  if (rc != SQLITE_OK) {
    std::fprintf(stderr, "Fixture SQL failed: %s\n", error ? error : "unknown");
    ++failures;
  }
  sqlite3_free(error);
}

struct FixtureDir {
  std::filesystem::path path;
  FixtureDir() {
    std::random_device random;
    for (int i = 0; i < 20; ++i) {
      auto candidate = std::filesystem::temp_directory_path() /
          ("kmap-storage-test-" + std::to_string(random()));
      if (std::filesystem::create_directory(candidate)) { path = candidate; return; }
    }
    throw std::runtime_error("cannot create unique fixture directory");
  }
  ~FixtureDir() {
    std::error_code ec;
    for (const char *name : {"legacy.db", "legacy.db-wal", "legacy.db-shm",
                             "broken.db", "broken.db-wal", "broken.db-shm"})
      std::filesystem::remove(path / name, ec);
    std::filesystem::remove(path, ec);
  }
};

static void test_ip_validation() {
  CHECK(ip_to_u32("203.0.113.10") == 0xcb00710au);
  CHECK(ip_to_u32("255.255.255.255") == 0xffffffffu);
  for (const char *invalid : {"203.0.113.10junk", "203.0.113.10/24",
                             " 203.0.113.10", "+203.0.113.10",
                             "203.0.113.10 ", "203.0.113.10.1",
                             "4294967499.0.113.10", "256.0.0.1", ""}) {
    uint32_t actual = ip_to_u32(invalid);
    if (actual != 0) std::fprintf(stderr, "Invalid IP '%s' aliased to %s\n",
                                 invalid, u32_to_ip(actual).c_str());
    CHECK(actual == 0);
  }
  for (uint32_t ip : {0u, 1u, 0x7f000001u, 0xc0000201u, 0xffffffffu})
    CHECK(ip_to_u32(u32_to_ip(ip).c_str()) == ip);
}

static void test_missing_latency(sqlite3 *db) {
  NetTopoEdge edge{};
  edge.from_u32 = 1; edge.to_u32 = 2; edge.path_count = 10; edge.last_seen = 1;
  CHECK(net_db_upsert_topo_edge(db, edge) == 0); // Ten paths, no RTT measurement.
  edge.path_count = 2; edge.avg_latency_ms = 20; edge.last_seen = 2;
  CHECK(net_db_upsert_topo_edge(db, edge) == 0);
  auto rows = net_db_get_topo_edges_from(db, 1);
  CHECK(rows.size() == 1);
  if (!rows.empty()) {
    std::printf("unknown-then-measured: latency=%.8f expected=20 paths=%lld\n",
                rows[0].avg_latency_ms, static_cast<long long>(rows[0].path_count));
    CHECK(std::abs(rows[0].avg_latency_ms - 20) < 1e-8);
    CHECK(rows[0].path_count == 12);
  }

  edge.from_u32 = 3; edge.to_u32 = 4; edge.path_count = 2; edge.avg_latency_ms = 10;
  CHECK(net_db_upsert_topo_edge(db, edge) == 0);
  edge.path_count = 100; edge.avg_latency_ms = 0;
  CHECK(net_db_upsert_topo_edge(db, edge) == 0);
  edge.path_count = 2; edge.avg_latency_ms = 30;
  CHECK(net_db_upsert_topo_edge(db, edge) == 0);
  rows = net_db_get_topo_edges_from(db, 3);
  CHECK(rows.size() == 1);
  if (!rows.empty()) {
    std::printf("measured-unknown-measured: latency=%.8f expected=20 paths=%lld\n",
                rows[0].avg_latency_ms, static_cast<long long>(rows[0].path_count));
    CHECK(std::abs(rows[0].avg_latency_ms - 20) < 1e-8);
    CHECK(rows[0].path_count == 104);
  }
}

static void test_intern_failure(sqlite3 *db) {
  sql(db, "CREATE TRIGGER reject_string BEFORE INSERT ON strings "
          "BEGIN SELECT RAISE(FAIL, 'fixture string write failure'); END;");
  NetTopoNode node{};
  node.ip_u32 = 0xc0000202u;
  node.hostname = "router.example.test";
  node.last_seen = 100;
  int result = net_db_upsert_topo_node(db, node);
  std::printf("failed string write: node result=%d expected=-1\n", result);
  CHECK(result == -1);
  NetTopoNode actual{};
  CHECK(!net_db_get_topo_node(db, node.ip_u32, &actual));
  sql(db, "DROP TRIGGER reject_string;");
  CHECK(net_db_upsert_topo_node(db, node) == 0);
  CHECK(net_db_get_topo_node(db, node.ip_u32, &actual));
  CHECK(actual.hostname == node.hostname);
  CHECK(actual.path_count == 1);
}

static void test_large_counts(sqlite3 *db) {
  NetTopoNode node{};
  node.ip_u32 = 0xc0000203u; node.path_count = 2147483647; node.last_seen = 1;
  CHECK(net_db_upsert_topo_node(db, node) == 0);
  node.path_count = 1;
  CHECK(net_db_upsert_topo_node(db, node) == 0);
  NetTopoNode actual{};
  CHECK(net_db_get_topo_node(db, node.ip_u32, &actual));
  std::printf("cumulative node count=%lld expected=2147483648\n",
              static_cast<long long>(actual.path_count));
  CHECK(actual.path_count == INT64_C(2147483648));
  NetTopoEdge edge{};
  edge.from_u32 = node.ip_u32; edge.to_u32 = node.ip_u32 + 1;
  edge.path_count = 2147483647; edge.last_seen = 1; edge.avg_latency_ms = 10;
  CHECK(net_db_upsert_topo_edge(db, edge) == 0);
  edge.path_count = 1;
  CHECK(net_db_upsert_topo_edge(db, edge) == 0);
  auto rows = net_db_get_topo_edges_from(db, edge.from_u32);
  CHECK(rows.size() == 1);
  if (!rows.empty()) CHECK(rows[0].path_count == INT64_C(2147483648));
  rows = net_db_get_topo_edges_to(db, edge.to_u32);
  CHECK(rows.size() == 1);
  if (!rows.empty()) CHECK(rows[0].path_count == INT64_C(2147483648));
}

static void make_legacy(const std::string &path, bool exhaust_columns) {
  sqlite3 *db = nullptr;
  CHECK(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
  if (!db) return;
  std::string schema = "CREATE TABLE hosts (ip TEXT NOT NULL, port INTEGER NOT NULL, "
          "proto TEXT DEFAULT 'tcp', first_seen INTEGER NOT NULL, "
          "last_seen INTEGER NOT NULL, service TEXT, version TEXT, cves TEXT, "
          "web_title TEXT, web_server TEXT, web_headers TEXT, web_paths TEXT, "
          "enriched INTEGER DEFAULT 0";
  // Leave room for exactly one migration, then force ADD COLUMN to fail.
  // This also verifies earlier successful DDL is rolled back atomically.
  if (exhaust_columns)
    for (int i = 13; i < sqlite3_limit(db, SQLITE_LIMIT_COLUMN, -1) - 1; ++i)
      schema += ", extra_" + std::to_string(i) + " TEXT";
  schema += ", PRIMARY KEY(ip,port));";
  sql(db, schema.c_str());
  sql(db,
          "INSERT INTO hosts(ip,port,first_seen,last_seen,service) "
          "VALUES('192.0.2.1',443,100,200,'https');"
          "CREATE TABLE topo_edges (from_u32 INTEGER, to_u32 INTEGER, "
          "asn_boundary INTEGER, avg_latency_ms REAL, path_count INTEGER, "
          "last_seen INTEGER, PRIMARY KEY(from_u32,to_u32));"
          "INSERT INTO topo_edges VALUES(5,6,0,10.0,2,100);");
  CHECK(sqlite3_close(db) == SQLITE_OK);
}

static void test_migrations(const FixtureDir &dir) {
  std::string legacy = (dir.path / "legacy.db").string();
  make_legacy(legacy, false);
  for (int pass = 0; pass < 2; ++pass) {
    sqlite3 *db = net_db_open(legacy);
    CHECK(db != nullptr);
    if (!db) continue;
    auto hosts = net_db_get_host(db, "192.0.2.1");
    CHECK(hosts.size() == 1);
    if (!hosts.empty()) {
      CHECK(hosts[0].first_seen == 100);
      CHECK(hosts[0].service == "https");
    }
    if (pass == 0) {
      NetTopoEdge e{}; e.from_u32 = 5; e.to_u32 = 6; e.path_count = 2;
      e.avg_latency_ms = 30; e.last_seen = 200;
      CHECK(net_db_upsert_topo_edge(db, e) == 0);
    }
    auto rows = net_db_get_topo_edges_from(db, 5);
    CHECK(rows.size() == 1);
    if (!rows.empty()) CHECK(std::abs(rows[0].avg_latency_ms - 20) < 1e-8);
    CHECK(sqlite3_next_stmt(db, nullptr) == nullptr);
    CHECK(sqlite3_close(db) == SQLITE_OK);
  }
  std::string broken = (dir.path / "broken.db").string();
  make_legacy(broken, true);
  sqlite3 *db = net_db_open(broken);
  std::printf("failed migration returned %s (expected null)\n", db ? "handle" : "null");
  CHECK(db == nullptr);
  if (db) {
    std::printf("unusable returned handle: host rows=%zu insert=%d\n",
                net_db_get_host(db, "192.0.2.1").size(),
                net_db_insert_host(db, 1, 80, "tcp", 1));
    net_db_close(db);
  }
  db = nullptr;
  CHECK(sqlite3_open(broken.c_str(), &db) == SQLITE_OK);
  if (db) {
    sqlite3_stmt *stmt = nullptr;
    CHECK(sqlite3_prepare_v2(db, "SELECT asn FROM hosts", -1, &stmt, nullptr)
          != SQLITE_OK); // The first migration must have been rolled back.
    if (stmt) sqlite3_finalize(stmt);
    stmt = nullptr;
    CHECK(sqlite3_prepare_v2(db, "SELECT * FROM fingerprints", -1, &stmt, nullptr)
          != SQLITE_OK); // New tables must also have been rolled back.
    if (stmt) sqlite3_finalize(stmt);
    CHECK(net_db_count(db) == 1); // The pre-existing host remains intact.
    CHECK(sqlite3_next_stmt(db, nullptr) == nullptr);
    CHECK(sqlite3_close(db) == SQLITE_OK);
  }
}

int main() {
  test_ip_validation();
  sqlite3 *db = net_db_open(":memory:");
  CHECK(db != nullptr);
  if (db) {
    test_missing_latency(db);
    test_intern_failure(db);
    test_large_counts(db);
    CHECK(sqlite3_next_stmt(db, nullptr) == nullptr);
    CHECK(sqlite3_close(db) == SQLITE_OK);
  }
  FixtureDir dir;
  test_migrations(dir);
  std::printf("net_db_regression_test: %d failure(s)\n", failures);
  return failures ? 1 : 0;
}
