/* Bounded real SQLite recovery/resource checks and small parity benchmark.
 * Uses only generated local files; no network or scanner execution. */
#include "net_db.h"
#include "entity_graph.h"
#include "third-party/nlohmann/json.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <random>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

static int failures = 0, closes = 0;
#define CHECK(x) do { if (!(x)) { ++failures; \
  std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); } } while (0)
static void sql(sqlite3 *db, const char *s) {
  int rc = sqlite3_exec(db, s, nullptr, nullptr, nullptr);
  if (rc != SQLITE_OK) { std::fprintf(stderr, "%s: %s\n", s, sqlite3_errmsg(db)); std::exit(2); }
}
static void close_db(sqlite3 *db) {
  CHECK(sqlite3_next_stmt(db, nullptr) == nullptr);
  int status = sqlite3_close(db);
  CHECK(status == SQLITE_OK);
  if (status == SQLITE_OK) ++closes;
}
struct Fixture {
  std::filesystem::path dir;
  Fixture() {
    std::random_device rng;
    for (int i = 0; i < 20; ++i) {
      auto path = std::filesystem::temp_directory_path() /
          ("kmap-db-lifecycle-" + std::to_string(rng()));
      if (std::filesystem::create_directory(path)) {
        dir = path;
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
    std::error_code ec;
    for (const auto &entry : std::filesystem::directory_iterator(dir, ec))
      if (entry.is_regular_file()) std::filesystem::remove(entry.path(), ec);
    std::filesystem::remove(dir, ec);
  }
};
static long handles() {
#ifdef _WIN32
  DWORD count = 0;
  CHECK(GetProcessHandleCount(GetCurrentProcess(), &count));
  return static_cast<long>(count);
#else
  return -1;
#endif
}
static void transaction_recovery(Fixture &fixture) {
  std::string path = fixture.path("commit.db");
  sqlite3 *db = net_db_open(path); CHECK(db); if (!db) return;
  sql(db, "PRAGMA journal_mode=DELETE");
  sqlite3 *reader = nullptr;
  CHECK(sqlite3_open(path.c_str(), &reader) == SQLITE_OK);
  sqlite3_busy_timeout(db, 0); sqlite3_busy_timeout(reader, 0);
  CHECK(net_db_begin(nullptr) == -1 && net_db_commit(nullptr) == -1);
  CHECK(net_db_rollback(nullptr) == -1);
  CHECK(net_db_rollback(db) == 0);
  CHECK(net_db_commit(db) == -1);
  CHECK(net_db_begin(db) == 0);
  CHECK(net_db_begin(db) == -1);
  CHECK(!sqlite3_get_autocommit(db));
  CHECK(net_db_rollback(db) == 0);
  for (bool retry : {true, false}) {
    sql(reader, "BEGIN");
    CHECK(net_db_count(reader) == (retry ? 0 : 1)); // retain a real read lock
    CHECK(net_db_begin(db) == 0);
    CHECK(net_db_insert_host(db, retry ? 1 : 2, 80, "tcp", 10) == 1);
    CHECK(net_db_commit(db) == -1); // SQLITE_BUSY, transaction remains active
    CHECK(!sqlite3_get_autocommit(db));
    CHECK(net_db_count(reader) == (retry ? 0 : 1));
    sql(reader, "ROLLBACK");
    if (retry) CHECK(net_db_commit(db) == 0);
    else CHECK(net_db_rollback(db) == 0);
    CHECK(sqlite3_get_autocommit(db));
    CHECK(net_db_count(reader) == 1);
  }
  close_db(reader); close_db(db);
  db = net_db_open(path); CHECK(db);
  if (db) { CHECK(net_db_count(db) == 1); close_db(db); }
}
static void emit_and_verify(Fixture &fixture, const NetHost &host) {
  std::string id = "ip:" + host.ip;
  std::map<std::string, EgNode> nodes{{id, {"ip", host.hostname}}};
  std::vector<EgEdge> edges;
  FILE *file = std::fopen(fixture.path("export.json").c_str(), "w+b");
  CHECK(file); if (!file) return;
  entity_graph_emit(file, "json", host.ip, 0, 0, nodes, edges);
  CHECK(std::fflush(file) == 0);
  long size = std::ftell(file);
  CHECK(size >= 0 && size < 4096);
  CHECK(std::fseek(file, 0, SEEK_SET) == 0);
  std::string text(size > 0 && size < 4096 ? static_cast<size_t>(size) : 0, '\0');
  CHECK(std::fread(text.data(), 1, text.size(), file) == text.size());
  CHECK(std::fclose(file) == 0);
  auto parsed = nlohmann::json::parse(text);
  CHECK(parsed["nodes"].size() == 1);
  CHECK(parsed["nodes"][0]["id"] == id);
  CHECK(parsed["nodes"][0]["label"] == host.hostname);
}
static void lifecycle(Fixture &fixture) {
  std::string path = fixture.path("cycles.db");
  // Warm up SQLite and the CRT before measuring this process's handles.
  sqlite3 *db = net_db_open(path); CHECK(db); if (!db) return;
  close_db(db);
  long first = handles(), peak = first;
  for (int cycle = 0; cycle < 100; ++cycle) {
    db = net_db_open(path); CHECK(db); if (!db) return;
    uint32_t ip = 0xc0000201u + cycle;
    std::string address = u32_to_ip(ip);
    CHECK(net_db_begin(db) == 0);
    CHECK(net_db_insert_host(db, ip, 80, "tcp", 10) == 1);
    CHECK(net_db_update_enrichment(db, address.c_str(), 80, "fixture", "1", "[]",
                                   nullptr, nullptr, nullptr, nullptr) == 0);
    CHECK(net_db_set_hostname(db, address.c_str(), "offline fixture") == 0);
    CHECK(net_db_insert_fingerprint(db, ip, 80, "hostname", "offline fixture", 10) == 0);
    CHECK(net_db_commit(db) == 0);
    CHECK(net_db_count(db) == cycle + 1);
    auto hosts = net_db_get_host(db, address.c_str());
    CHECK(hosts.size() == 1);
    if (!hosts.empty()) emit_and_verify(fixture, hosts.front());
    CHECK(net_db_get_fingerprints_for_ip(db, address.c_str()).size() == 1);
    std::string error;
    auto hits = net_db_search_fts(db, "fixture", 200, &error);
    CHECK(error.empty() && hits.size() == static_cast<size_t>(cycle + 1));
    error.clear();
    CHECK(net_db_search_fts(db, "\"", 200, &error).empty());
    CHECK(!error.empty());
    sql(db, "PRAGMA query_only=ON");
    NetDbOpen rejected{0xcb007101u, 80, 11};
    CHECK(net_db_insert_opens_bulk(db, &rejected, 1) == -1);
    CHECK(net_db_count(db) == cycle + 1);
    sql(db, "PRAGMA query_only=OFF");
    CHECK(net_db_begin(db) == 0);
    CHECK(net_db_insert_host(db, 0xcb007101u, 80, "tcp", 11) == 1);
    // Closing without COMMIT must discard only the unfinished transaction.
    close_db(db);
    db = net_db_open(path); CHECK(db); if (!db) return;
    CHECK(net_db_count(db) == cycle + 1);
    CHECK(net_db_get_host(db, "203.0.113.1").empty());
    close_db(db);
    long current = handles();
    if (current > peak) peak = current;
    if (first >= 0) CHECK(current <= first);
  }
  std::printf("lifecycle cycles=100 handles_before=%ld handles_after=%ld peak_after_close=%ld\n",
              first, handles(), peak);
}
static void benchmark() {
  using Clock = std::chrono::steady_clock;
  for (int count : {32, 128, 512}) {
    double single_ms = 0, bulk_ms = 0;
    for (int repeat = 0; repeat < 3; ++repeat) {
      sqlite3 *single = net_db_open(":memory:");
      sqlite3 *bulk = net_db_open(":memory:");
      CHECK(single && bulk); if (!single || !bulk) std::exit(2);
      std::vector<NetDbOpen> rows;
      for (int i = 0; i < count; ++i)
        rows.push_back({static_cast<uint32_t>(0xc0000201u + i / 2), 80, i + 1});
      CHECK(net_db_begin(single) == 0 && net_db_begin(bulk) == 0);
      auto start = Clock::now();
      for (const auto &row : rows)
        CHECK(net_db_insert_host(single, row.ip, row.port, "tcp", row.ts) == 1);
      single_ms += std::chrono::duration<double, std::milli>(Clock::now() - start).count();
      start = Clock::now();
      CHECK(net_db_insert_opens_bulk(bulk, rows.data(), rows.size()) == count);
      bulk_ms += std::chrono::duration<double, std::milli>(Clock::now() - start).count();
      CHECK(net_db_commit(single) == 0 && net_db_commit(bulk) == 0);
      CHECK(net_db_count(single) == count / 2 && net_db_count(bulk) == count / 2);
      for (int i = 0; i < count / 2; ++i) {
        std::string ip = u32_to_ip(0xc0000201u + i);
        auto a = net_db_get_host(single, ip.c_str());
        auto b = net_db_get_host(bulk, ip.c_str());
        CHECK(a.size() == 1 && b.size() == 1);
        if (!a.empty() && !b.empty()) {
          CHECK(a[0].first_seen == b[0].first_seen);
          CHECK(a[0].last_seen == b[0].last_seen);
          CHECK(a[0].scan_count == 2 && b[0].scan_count == 2);
        }
      }
      close_db(single); close_db(bulk);
    }
    std::printf("parity benchmark rows=%d repeats=3 single_ms_total=%.3f bulk_ms_total=%.3f\n",
                count, single_ms, bulk_ms);
  }
}
int main() {
  Fixture fixture;
  transaction_recovery(fixture); lifecycle(fixture); benchmark();
  std::printf("storage lifecycle: closes=%d failed_assertions=%d\n", closes, failures);
  return failures ? 1 : 0;
}
