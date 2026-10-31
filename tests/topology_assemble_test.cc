/* Actual shipping topology assembler, exercised only with recorded fixtures.
 * No traceroute, DNS, sockets or external programs are involved. */
#include "../topology_assemble.h"
#include "../topology_store.h"
#include "../net_db.h"
#include <array>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <filesystem>
#include <random>
#include <cstring>

static int failures = 0;
#define CHECK(expr) do { if (!(expr)) { \
  std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
  ++failures; } } while (0)
static bool near(double a, double b) { return std::abs(a - b) < 1e-9; }
static const char *SOURCE = "192.0.2.1", *A = "192.0.2.2", *B = "192.0.2.3";

static TraceResult trace(double a, double b) {
  TraceResult result{};
  result.target_ip = B; result.reached = true; result.hops_used = 2;
  TraceHop first{}; first.ttl = 1; first.ip = A; first.rtt_ms = a;
  TraceHop second{}; second.ttl = 2; second.ip = B; second.rtt_ms = b;
  result.hops = {first, second};
  return result;
}
static const TopoNode &node(const Topology &t, const char *ip) {
  for (const auto &n : t.nodes) if (n.ip == ip) return n;
  throw std::runtime_error("missing node");
}
static const TopoEdge &edge(const Topology &t) {
  for (const auto &e : t.edges) if (e.from_ip == A && e.to_ip == B) return e;
  throw std::runtime_error("missing edge");
}

static void persist(sqlite3 *db, const Topology &topology) {
  int nodes = 0, edges = 0;
  CHECK(persist_topology(db, topology, 1, nodes, edges));
  CHECK(nodes == static_cast<int>(topology.nodes.size()));
  CHECK(edges == static_cast<int>(topology.edges.size()));
}

static void check_store(sqlite3 *db, const Topology &expected) {
  for (const auto &n : expected.nodes) {
    NetTopoNode got{};
    CHECK(net_db_get_topo_node(db, ip_to_u32(n.ip.c_str()), &got));
    CHECK(got.path_count == n.path_count);
    CHECK(got.rtt_sample_count == n.rtt_sample_count);
    CHECK(near(got.avg_rtt_ms, n.avg_rtt_ms));
  }
  for (const auto &e : expected.edges) {
    auto rows = net_db_get_topo_edges_from(db, ip_to_u32(e.from_ip.c_str()));
    CHECK(rows.size() == 1);
    if (rows.empty()) continue;
    CHECK(rows[0].path_count == e.path_count);
    CHECK(rows[0].latency_sample_count == e.latency_sample_count);
    CHECK(near(rows[0].avg_latency_ms, e.avg_latency_ms));
  }
}

static void legacy_migration() {
  std::filesystem::path directory;
  std::random_device random;
  for (int attempt = 0; attempt < 20; ++attempt) {
    auto candidate = std::filesystem::temp_directory_path() /
        ("kmap-topology-migration-" + std::to_string(random()));
    if (std::filesystem::create_directory(candidate)) { directory = candidate; break; }
  }
  CHECK(!directory.empty());
  if (directory.empty()) return;
  std::string path = (directory / "legacy.db").string();
  sqlite3 *db = nullptr;
  CHECK(sqlite3_open(path.c_str(), &db) == SQLITE_OK);
  const char *schema =
    "CREATE TABLE topo_nodes(ip_u32 INTEGER PRIMARY KEY, hostname_id INTEGER, "
    "asn INTEGER, as_name_id INTEGER, country TEXT, role TEXT, path_count INTEGER, "
    "avg_rtt_ms REAL, last_seen INTEGER);"
    "INSERT INTO topo_nodes VALUES(1,NULL,0,NULL,'','',2,10.0,1);"
    "CREATE TABLE topo_edges(from_u32 INTEGER, to_u32 INTEGER, asn_boundary INTEGER, "
    "avg_latency_ms REAL, path_count INTEGER, last_seen INTEGER, "
    "PRIMARY KEY(from_u32,to_u32));"
    "INSERT INTO topo_edges VALUES(1,2,0,10.0,2,1);";
  CHECK(sqlite3_exec(db, schema, nullptr, nullptr, nullptr) == SQLITE_OK);
  CHECK(sqlite3_close(db) == SQLITE_OK);
  for (int pass = 0; pass < 2; ++pass) {
    db = net_db_open(path);
    CHECK(db != nullptr);
    if (!db) continue;
    if (pass == 0) {
      NetTopoNode n{};
      n.ip_u32 = 1; n.path_count = 10; n.rtt_sample_count = 2;
      n.avg_rtt_ms = 30; n.last_seen = 2;
      CHECK(net_db_upsert_topo_node(db, n) == 0);
      NetTopoEdge e{};
      e.from_u32 = 1; e.to_u32 = 2; e.path_count = 10; e.latency_sample_count = 2;
      e.avg_latency_ms = 30; e.last_seen = 2;
      CHECK(net_db_upsert_topo_edge(db, e) == 0);
    }
    NetTopoNode n{};
    CHECK(net_db_get_topo_node(db, 1, &n));
    CHECK(n.path_count == 12 && n.rtt_sample_count == 4 && near(n.avg_rtt_ms, 20));
    auto edges = net_db_get_topo_edges_from(db, 1);
    CHECK(edges.size() == 1);
    if (!edges.empty()) CHECK(edges[0].path_count == 12 && edges[0].latency_sample_count == 4 &&
                              near(edges[0].avg_latency_ms, 20));
    CHECK(sqlite3_close(db) == SQLITE_OK);
  }
  if (failures) {
    std::fprintf(stderr, "retained migration fixtures: %s\n", directory.string().c_str());
    return;
  }
  std::error_code error;
  for (const char *name : {"legacy.db", "legacy.db-wal", "legacy.db-shm", "legacy.db-journal"})
    std::filesystem::remove(directory / name, error);
  std::filesystem::remove(directory, error);
}

static int deny_commit(void *, int action, const char *operation,
                       const char *, const char *, const char *) {
  return action == SQLITE_TRANSACTION && operation &&
         std::strcmp(operation, "COMMIT") == 0 ? SQLITE_DENY : SQLITE_OK;
}

static void persistence_failures() {
  sqlite3 *db = net_db_open(":memory:");
  CHECK(db != nullptr);
  if (!db) return;
  const auto graph = build_topology({trace(10, 20)}, SOURCE);
  const char *reject_edge = "CREATE TRIGGER reject_edge BEFORE INSERT ON topo_edges "
                            "BEGIN SELECT RAISE(ABORT,'fixture rejected edge'); END";
  CHECK(sqlite3_exec(db, reject_edge, nullptr, nullptr, nullptr) == SQLITE_OK);
  int nodes = -1, edges = -1;
  CHECK(!persist_topology(db, graph, 1, nodes, edges));
  CHECK(nodes == 0 && edges == 0);
  CHECK(net_db_count_topo_nodes(db) == 0 && net_db_count_topo_edges(db) == 0);
  CHECK(sqlite3_get_autocommit(db) != 0);
  CHECK(sqlite3_exec(db, "DROP TRIGGER reject_edge", nullptr, nullptr, nullptr) == SQLITE_OK);

  CHECK(sqlite3_set_authorizer(db, deny_commit, nullptr) == SQLITE_OK);
  CHECK(!persist_topology(db, graph, 1, nodes, edges));
  CHECK(nodes == 0 && edges == 0);
  CHECK(sqlite3_get_autocommit(db) != 0);
  CHECK(sqlite3_set_authorizer(db, nullptr, nullptr) == SQLITE_OK);
  CHECK(net_db_count_topo_nodes(db) == 0 && net_db_count_topo_edges(db) == 0);
  persist(db, graph);
  check_store(db, graph);
  CHECK(sqlite3_next_stmt(db, nullptr) == nullptr);
  CHECK(sqlite3_close(db) == SQLITE_OK);
}

int main() {
  persistence_failures();
  legacy_migration();
  auto first = trace(10, 20), second = trace(30, 40);
  auto forward = build_topology({first, second}, SOURCE);
  auto reverse = build_topology({second, first}, SOURCE);
  CHECK(near(edge(forward).avg_latency_ms, 10));
  CHECK(near(edge(reverse).avg_latency_ms, 10));
  CHECK(near(node(forward, A).avg_rtt_ms, 20));
  CHECK(edge(forward).latency_sample_count == 2);

  // Unknown RTTs must not become artificial zero measurements; known zero
  // RTTs are real observations and must remain in the mean/count.
  auto zero = build_topology({trace(0, 0), trace(10, 20)}, SOURCE);
  CHECK(near(node(zero, A).avg_rtt_ms, 5));
  CHECK(node(zero, A).rtt_sample_count == 2);
  CHECK(near(edge(zero).avg_latency_ms, 5));
  CHECK(edge(zero).latency_sample_count == 2);
  sqlite3 *db = net_db_open(":memory:");
  CHECK(db != nullptr);
  if (db) {
    auto zero_only = build_topology({trace(0, 0)}, SOURCE);
    persist(db, zero_only); check_store(db, zero_only);
    persist(db, build_topology({trace(10, 20)}, SOURCE));
    check_store(db, zero);
    NetTopoEdge invalid_count{};
    invalid_count.from_u32 = 10; invalid_count.to_u32 = 11;
    invalid_count.path_count = 1; invalid_count.latency_sample_count = 2;
    invalid_count.avg_latency_ms = 10;
    CHECK(net_db_upsert_topo_edge(db, invalid_count) == -1);
    CHECK(net_db_get_topo_edges_from(db, 10).empty());
    NetTopoNode invalid_node{};
    invalid_node.ip_u32 = 10; invalid_node.rtt_sample_count = 1;
    invalid_node.avg_rtt_ms = std::numeric_limits<double>::infinity();
    CHECK(net_db_upsert_topo_node(db, invalid_node) == -1);
    net_db_close(db);
  }

  auto unknown = build_topology({trace(-1, -1)}, SOURCE);
  CHECK(node(unknown, A).rtt_sample_count == 0);
  CHECK(edge(unknown).latency_sample_count == 0);
  auto invalid = build_topology({trace(std::numeric_limits<double>::infinity(), 20)}, SOURCE);
  CHECK(node(invalid, A).rtt_sample_count == 0);
  CHECK(edge(invalid).latency_sample_count == 0);

  std::array<TraceResult, 4> observations{{trace(10, 30), trace(-1, 30),
                                         trace(30, 40), trace(50, -1)}};
  std::array<int, 4> order{{0, 1, 2, 3}};
  int permutations = 0, partitions = 0;
  do {
    std::vector<TraceResult> traces;
    for (int index : order) traces.push_back(observations[index]);
    auto expected = build_topology(traces, SOURCE);
    CHECK(near(node(expected, A).avg_rtt_ms, 30));
    CHECK(node(expected, A).rtt_sample_count == 3);
    CHECK(near(edge(expected).avg_latency_ms, 15));
    CHECK(edge(expected).path_count == 4);
    CHECK(edge(expected).latency_sample_count == 2);
    for (int batch_size : {1, 2, 3, 4}) {
      db = net_db_open(":memory:");
      CHECK(db != nullptr);
      if (!db) continue;
      for (size_t begin = 0; begin < traces.size(); begin += batch_size) {
        size_t end = std::min(traces.size(), begin + batch_size);
        std::vector<TraceResult> batch(traces.begin() + begin, traces.begin() + end);
        persist(db, build_topology(batch, SOURCE));
      }
      check_store(db, expected);
      CHECK(sqlite3_next_stmt(db, nullptr) == nullptr);
      CHECK(sqlite3_close(db) == SQLITE_OK);
      ++partitions;
    }
    ++permutations;
  } while (std::next_permutation(order.begin(), order.end()));
  std::printf("topology assembly: %d permutations, %d persisted batch partitions, %d failures\n",
              permutations, partitions, failures);
  return failures ? 1 : 0;
}
