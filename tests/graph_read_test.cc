/* Offline production graph/read contracts: failed reads never look complete. */
#include "../entity_graph.h"
#include "../net_db.h"
#include <filesystem>
#include <array>
#include <algorithm>
#include <fstream>
#include <random>
#include <set>

static int checks = 0, failures = 0;
#define CHECK(c) do { ++checks; if (!(c)) { ++failures; \
  std::fprintf(stderr, "line %d: %s\n", __LINE__, #c); } } while (0)

struct Fixture {
  std::filesystem::path root;
  int failures_at_start = failures;
  Fixture() {
    std::random_device random;
    for (int i = 0; i < 20; ++i) {
      auto p = std::filesystem::temp_directory_path() /
          ("kmap-graph-read-" + std::to_string(random()));
      if (std::filesystem::create_directory(p)) { root = p; return; }
    }
    throw std::runtime_error("cannot create owned graph fixture directory");
  }
  ~Fixture() {
    if (failures > failures_at_start || std::uncaught_exceptions() > 0) {
      std::fprintf(stderr, "graph_read_test: retained failing fixture %s\n", root.string().c_str());
      return;
    }
    std::error_code error;
    std::filesystem::remove_all(root, error);
  }
};

static void fingerprint(const std::filesystem::path &dir, uint32_t ip,
                        const char *value) {
  auto db = net_db_open(net_shard_path(dir.string().c_str(), net_shard_index(ip)));
  CHECK(db != nullptr);
  if (!db) return;
  CHECK(net_db_insert_fingerprint(db, ip, 443, "tls_san", value, 200) == 0);
  net_db_close(db);
}

static void read_errors() {
  sqlite3 *db = net_db_open(":memory:");
  CHECK(db != nullptr);
  if (!db) return;
  const uint32_t ip = ip_to_u32("192.0.2.10");
  CHECK(net_db_begin(db) == 0);
  for (int i = 1; i <= 1024; ++i) {
    CHECK(net_db_insert_host(db, ip, i, "tcp", 100) == 1);
    CHECK(net_db_insert_fingerprint(db, ip, 443, "hostname",
                                   std::to_string(i).c_str(), 200) == 0);
    CHECK(net_db_insert_fingerprint(db, ip + i, 443, "tls_san", "shared.test", 200) == 0);
  }
  CHECK(net_db_commit(db) == 0);
  std::string error = "stale";
  CHECK(net_db_get_host(db, "192.0.2.10", &error).size() == 1024 && error.empty());
  CHECK(net_db_get_host(db, "192.0.2.11", &error).empty() && error.empty());
  CHECK(net_db_get_fingerprints_for_ip(db, "192.0.2.10", &error).size() == 1024 && error.empty());
  CHECK(net_db_find_by_fingerprint(db, "tls_san", "shared.test", &error).size() == 1024 && error.empty());
  auto limited = net_db_find_by_fingerprint(db, "tls_san", "shared.test", &error, 7);
  CHECK(limited.size() == 7 && error.empty());
  CHECK(limited.front().ip_u32 == ip + 1 && limited.back().ip_u32 == ip + 7);
  CHECK(net_db_find_by_fingerprint(db, "tls_san", "absent", &error).empty() && error.empty());
  auto denied = [](void *, int action, const char *, const char *, const char *, const char *) {
    return action == SQLITE_READ ? SQLITE_DENY : SQLITE_OK;
  };
  sqlite3_set_authorizer(db, denied, nullptr);
  CHECK(net_db_get_host(db, "192.0.2.10", &error).empty() && !error.empty());
  CHECK(net_db_get_fingerprints_for_ip(db, "192.0.2.10", &error).empty() && !error.empty());
  CHECK(net_db_find_by_fingerprint(db, "tls_san", "shared.test", &error).empty() && !error.empty());
  sqlite3_set_authorizer(db, nullptr, nullptr);
  // Interrupt after some execution, rather than only rejecting prepare.
  auto interrupt = [](void *context) -> int { return --*static_cast<int *>(context) <= 0; };
  int budget = 500;
  sqlite3_progress_handler(db, 1, interrupt, &budget);
  CHECK(net_db_get_host(db, "192.0.2.10", &error).empty() && !error.empty() && budget <= 0);
  budget = 500;
  CHECK(net_db_get_fingerprints_for_ip(db, "192.0.2.10", &error).empty() && !error.empty() && budget <= 0);
  budget = 500;
  CHECK(net_db_find_by_fingerprint(db, "tls_san", "shared.test", &error).empty() && !error.empty() && budget <= 0);
  sqlite3_progress_handler(db, 0, nullptr, nullptr);
  CHECK(net_db_get_host(db, "192.0.2.10", &error).size() == 1024 && error.empty());
  int old_limit = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 1000);
  std::string too_long(1001, 'x');
  CHECK(net_db_get_host(db, too_long.c_str(), &error).empty() && !error.empty());
  CHECK(net_db_find_by_fingerprint(db, "hostname", too_long.c_str(), &error).empty() && !error.empty());
  sqlite3_limit(db, SQLITE_LIMIT_LENGTH, old_limit);
  CHECK(net_db_find_by_fingerprint(db, "tls_san", "shared.test", &error).size() == 1024 && error.empty());
  CHECK(net_db_get_host(nullptr, "192.0.2.10", &error).empty() && !error.empty());
  CHECK(net_db_get_fingerprints_for_ip(db, "invalid", &error).empty() && !error.empty());
  CHECK(sqlite3_next_stmt(db, nullptr) == nullptr);
  CHECK(sqlite3_close(db) == SQLITE_OK);
}

static void graph_depth_and_errors() {
  Fixture f;
  auto dir = f.root.string();
  const uint32_t a = ip_to_u32("192.0.2.10"), b = ip_to_u32("203.0.113.20");
  const uint32_t c = ip_to_u32("198.51.100.30"), d = ip_to_u32("203.0.113.40");
  fingerprint(f.root, a, "a.test");
  fingerprint(f.root, b, "a.test"); fingerprint(f.root, b, "b.test");
  fingerprint(f.root, c, "b.test"); fingerprint(f.root, c, "c.test");
  fingerprint(f.root, d, "c.test");
  // Refreshing a fingerprint on another port must not duplicate a peer.
  fingerprint(f.root, b, "a.test");
  {
    auto db = net_db_open(net_shard_path(dir.c_str(), net_shard_index(b)));
    CHECK(db != nullptr);
    if (!db) return;
    CHECK(net_db_begin(db) == 0);
    for (int port = 1; port <= 1100; ++port)
      CHECK(net_db_insert_fingerprint(db, b, port, "tls_san", "a.test", 200) == 0);
    CHECK(net_db_insert_fingerprint(db, d, 443, "tls_san", "port-control.test", 200) == 0);
    CHECK(net_db_commit(db) == 0);
    std::string error;
    auto rows = net_db_find_by_fingerprint(db, "tls_san", "a.test", &error, 1001);
    CHECK(rows.size() == 1 && rows[0].ip_u32 == b && error.empty());
    // Same value now on another IP still yields two rows even though the
    // first peer was observed on more ports than the graph lookup limit.
    CHECK(net_db_insert_fingerprint(db, d, 443, "tls_san", "a.test", 200) == 0);
    rows = net_db_find_by_fingerprint(db, "tls_san", "a.test", &error, 1001);
    CHECK(rows.size() == 2 && rows[0].ip_u32 == b && rows[1].ip_u32 == d && error.empty());
    net_db_close(db);
    std::map<std::string, EgNode> port_nodes;
    std::vector<EgEdge> port_edges;
    size_t peers = 0;
    CHECK(entity_graph_build(dir.c_str(), "192.0.2.10", 1, port_nodes, port_edges, &peers, &error) == 0);
    CHECK(peers == 2 && port_nodes.count("ip:" + u32_to_ip(b)) && port_nodes.count("ip:" + u32_to_ip(d)));
    db = net_db_open(net_shard_path(dir.c_str(), net_shard_index(b)));
    CHECK(db != nullptr);
    if (!db) return;
    CHECK(sqlite3_exec(db, ("DELETE FROM fingerprints WHERE value='a.test' AND ip_u32=" + std::to_string(d)).c_str(),
                      nullptr, nullptr, nullptr) == SQLITE_OK);
    net_db_close(db);
  }
  std::map<std::string, EgNode> nodes;
  std::vector<EgEdge> edges;
  size_t cohort = 99;
  std::string error;
  for (int depth = 0; depth <= 3; ++depth) {
    CHECK(entity_graph_build(dir.c_str(), "192.0.2.10", depth, nodes, edges, &cohort, &error) == 0);
    CHECK(error.empty() && cohort == static_cast<size_t>(depth));
    CHECK(nodes.count("ip:192.0.2.10") == 1);
    CHECK(nodes.count("ip:203.0.113.20") == (depth >= 1 ? 1u : 0u));
    CHECK(nodes.count("ip:198.51.100.30") == (depth >= 2 ? 1u : 0u));
    CHECK(nodes.count("ip:203.0.113.40") == (depth >= 3 ? 1u : 0u));
    std::set<std::string> unique;
    for (const auto &edge : edges) {
      CHECK(nodes.count(edge.from) == 1 && nodes.count(edge.to) == 1);
      CHECK(unique.insert(edge.from + "|" + edge.to + "|" + edge.label).second);
    }
  }
  CHECK(entity_graph_build(dir.c_str(), "bad", 1, nodes, edges, &cohort, &error) == -1);
  CHECK(nodes.empty() && edges.empty() && cohort == 0);
  CHECK(entity_graph_build(dir.c_str(), "192.0.2.10", 4, nodes, edges, &cohort, &error) == -1);
  // A corrupt populated peer shard must not become a successful empty cohort.
  auto peer = net_shard_path(dir.c_str(), net_shard_index(b));
  { std::ofstream bad(peer, std::ios::binary | std::ios::trunc); bad << "inert corrupt fixture"; }
  CHECK(entity_graph_build(dir.c_str(), "192.0.2.10", 1, nodes, edges, &cohort, &error) == -3);
  CHECK(!error.empty() && nodes.empty() && edges.empty() && cohort == 0);
  CHECK(entity_graph_build(dir.c_str(), "192.0.2.10", 0, nodes, edges, &cohort, &error) == 0);
}

static void graph_cap() {
  Fixture f;
  auto dir = f.root.string();
  uint32_t seed = ip_to_u32("192.0.2.1");
  auto db = net_db_open(net_shard_path(dir.c_str(), net_shard_index(seed)));
  CHECK(db != nullptr);
  if (!db) return;
  CHECK(net_db_begin(db) == 0);
  for (int i = 0; i <= 501; ++i)
    CHECK(net_db_insert_fingerprint(db, seed + i, 443, "tls_san", "cap.test", 200) == 0);
  CHECK(net_db_commit(db) == 0);
  net_db_close(db);
  std::map<std::string, EgNode> nodes;
  std::vector<EgEdge> edges;
  size_t cohort;
  std::string error;
  bool limit_reached = false;
  CHECK(entity_graph_build(dir.c_str(), "192.0.2.1", 3, nodes, edges, &cohort, &error, &limit_reached) == 0);
  CHECK(limit_reached);
  CHECK(error.empty() && cohort == 500 && nodes.size() == 502 && edges.size() == 501);
  CHECK(nodes.count("ip:" + u32_to_ip(seed + 500)) == 1);
  CHECK(nodes.count("ip:" + u32_to_ip(seed + 501)) == 0);
  auto previous_edges = edges.size();
  CHECK(entity_graph_build(dir.c_str(), "192.0.2.1", 3, nodes, edges, &cohort, &error) == 0);
  CHECK(cohort == 500 && nodes.size() == 502 && edges.size() == previous_edges);
}

static void graph_properties() {
  // Independent oracle: all-pairs shortest paths over assigned token sets,
  // rather than the production BFS implementation or database queries.
  for (unsigned seed : {1u, 1337u}) {
    std::mt19937 random(seed);
    for (int trial = 0; trial < 50; ++trial) {
      Fixture f;
      auto dir = f.root.string();
      const uint32_t base = ip_to_u32("192.0.2.1");
      auto db = net_db_open(net_shard_path(dir.c_str(), net_shard_index(base)));
      CHECK(db != nullptr);
      if (!db) return;
      std::array<unsigned, 8> domains{}, certs{};
      CHECK(net_db_begin(db) == 0);
      for (int host = 0; host < 8; ++host) {
        CHECK(net_db_insert_fingerprint(db, base + host, 443, "hostname",
            ("unique-" + std::to_string(host) + ".test").c_str(), 200) == 0);
        for (int token = 0; token < 6; ++token) {
          if (random() % 3 == 0) {
            domains[host] |= 1u << token;
            const char *kinds[] = {"hostname", "tls_san", "tls_subject_cn"};
            CHECK(net_db_insert_fingerprint(db, base + host, 443, kinds[random() % 3],
                ("domain-" + std::to_string(token) + ".test").c_str(), 200) == 0);
          }
          if (random() % 4 == 0) {
            certs[host] |= 1u << token;
            CHECK(net_db_insert_fingerprint(db, base + host, 443, "tls_sha256",
                ("cert-" + std::to_string(token)).c_str(), 200) == 0);
          }
        }
      }
      CHECK(net_db_commit(db) == 0);
      net_db_close(db);
      int distance[8][8];
      for (int a = 0; a < 8; ++a)
        for (int b = 0; b < 8; ++b)
          distance[a][b] = a == b ? 0 :
              ((domains[a] & domains[b]) || (certs[a] & certs[b])) ? 1 : 100;
      for (int through = 0; through < 8; ++through)
        for (int a = 0; a < 8; ++a)
          for (int b = 0; b < 8; ++b)
            distance[a][b] = (std::min)(distance[a][b], distance[a][through] + distance[through][b]);
      for (int depth = 0; depth <= 3; ++depth) {
        std::map<std::string, EgNode> nodes;
        std::vector<EgEdge> edges;
        size_t cohort = 0, expected = 0;
        std::string error;
        bool limit_reached = true;
        CHECK(entity_graph_build(dir.c_str(), "192.0.2.1", depth, nodes, edges, &cohort, &error, &limit_reached) == 0);
        CHECK(error.empty() && !limit_reached);
        for (int host = 0; host < 8; ++host) {
          bool reachable = distance[0][host] <= depth;
          CHECK(nodes.count("ip:" + u32_to_ip(base + host)) == (reachable ? 1u : 0u));
          if (reachable && host != 0) ++expected;
        }
        CHECK(cohort == expected);
      }
    }
    std::printf("graph_read_test: property seed %u, 50 graphs, depths 0..3\n", seed);
  }
}

int main() {
  try { read_errors(); graph_depth_and_errors(); graph_cap(); graph_properties(); }
  catch (const std::exception &error) { std::fprintf(stderr, "%s\n", error.what()); return 2; }
  std::printf("graph_read_test: %d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
