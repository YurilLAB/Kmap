/* net_db_topo_test.cc -- E2E test of persistent-topology + string
 * interning helpers against a real SQLite database.
 *
 * Validates:
 *   - strings table dedups on val (UNIQUE), returns the same id
 *     for repeated interns of the same value.
 *   - topo_nodes UPSERT is idempotent: repeat insert of the same IP
 *     bumps path_count but does not duplicate the row, and partial
 *     re-observations do not wipe previously-captured hostname/asn.
 *   - topo_edges UPSERT bumps path_count and updates avg_latency via
 *     the running-mean formula.
 *   - get_topo_edges_from / _to return matching rows.
 *   - get_topo_node resolves interned hostname / as_name back to
 *     literal strings via the LEFT JOIN.
 *
 * Build:
 *   g++ -o net_db_topo_test \
 *       tests/net_db_topo_test.cc net_db.cc sqlite/sqlite3.o
 */

#include "../net_db.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

static int g_failures = 0;

#define CHECK(expr) do { \
    if (!(expr)) { \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
      ++g_failures; \
    } \
  } while (0)

static void test_intern_dedups(sqlite3 *db) {
  int64_t a = net_db_intern_string(db, "CLOUDFLARENET");
  int64_t b = net_db_intern_string(db, "CLOUDFLARENET");
  CHECK(a > 0);
  CHECK(a == b);  /* same value -> same id */

  int64_t c = net_db_intern_string(db, "GOOGLE");
  CHECK(c > 0);
  CHECK(c != a);  /* distinct values -> distinct ids */

  /* Reverse lookup */
  CHECK(net_db_lookup_string(db, a) == "CLOUDFLARENET");
  CHECK(net_db_lookup_string(db, c) == "GOOGLE");

  /* Empty / NULL: id 0, lookup returns empty string */
  CHECK(net_db_intern_string(db, "") == 0);
  CHECK(net_db_intern_string(db, nullptr) == 0);
  CHECK(net_db_lookup_string(db, 0) == "");
}

static void test_topo_node_upsert_idempotent(sqlite3 *db) {
  uint32_t ip = ip_to_u32("8.8.8.8");
  NetTopoNode n{};
  n.ip_u32     = ip;
  n.hostname   = "dns.google";
  n.asn        = 15169;
  n.as_name    = "GOOGLE";
  n.country    = "US";
  n.role       = "target";
  n.avg_rtt_ms = 5.0;
  n.last_seen  = 1000;

  CHECK(net_db_upsert_topo_node(db, n) == 0);
  CHECK(net_db_count_topo_nodes(db) == 1);

  /* Repeat: same IP, no duplicate.  path_count bumps to 2. */
  n.last_seen = 2000;
  CHECK(net_db_upsert_topo_node(db, n) == 0);
  CHECK(net_db_count_topo_nodes(db) == 1);

  NetTopoNode got{};
  CHECK(net_db_get_topo_node(db, ip, &got));
  CHECK(got.hostname == "dns.google");
  CHECK(got.asn == 15169);
  CHECK(got.as_name == "GOOGLE");
  CHECK(got.path_count == 2);
  CHECK(got.last_seen == 2000);
}

static void test_topo_node_partial_reobservation_keeps_data(sqlite3 *db) {
  /* Re-observe the same IP but with empty hostname / as_name fields
     (e.g. a quick retrace where ASN lookup was skipped).  Previously-
     captured data must NOT be wiped. */
  uint32_t ip = ip_to_u32("8.8.8.8");
  NetTopoNode skinny{};
  skinny.ip_u32    = ip;
  /* hostname, as_name, country, role all empty */
  skinny.last_seen = 3000;

  CHECK(net_db_upsert_topo_node(db, skinny) == 0);

  NetTopoNode got{};
  CHECK(net_db_get_topo_node(db, ip, &got));
  /* The values from the earlier full insert must still be there. */
  CHECK(got.hostname == "dns.google");
  CHECK(got.as_name  == "GOOGLE");
  CHECK(got.country  == "US");
  CHECK(got.role     == "target");
  CHECK(got.last_seen == 3000);  /* but last_seen DID refresh */
}

static void test_topo_edge_upsert_and_running_mean(sqlite3 *db) {
  uint32_t a = ip_to_u32("10.0.0.1");
  uint32_t b = ip_to_u32("10.0.0.2");

  NetTopoEdge e1{};
  e1.from_u32       = a;
  e1.to_u32         = b;
  e1.asn_boundary   = 0;
  e1.avg_latency_ms = 10.0;
  e1.last_seen      = 1000;
  CHECK(net_db_upsert_topo_edge(db, e1) == 0);

  NetTopoEdge e2 = e1;
  e2.avg_latency_ms = 20.0;
  e2.last_seen      = 2000;
  CHECK(net_db_upsert_topo_edge(db, e2) == 0);

  /* Only one row — UPSERT collapsed the duplicate. */
  CHECK(net_db_count_topo_edges(db) == 1);

  auto outs = net_db_get_topo_edges_from(db, a);
  CHECK(outs.size() == 1);
  if (!outs.empty()) {
    /* Running mean after first sample = 10.0 (avg_old=NULL coalesced
       to 0, sample=10, n=1: 0 + (10-0)/1 = 10 after first insert).
       Wait — that's actually wrong: on first INSERT we just set
       avg_latency_ms = 10 directly.  On second insert (the UPSERT
       branch), avg_old=10, sample=20, n=2: 10 + (20-10)/2 = 15. */
    CHECK(outs[0].path_count == 2);
    CHECK(outs[0].avg_latency_ms > 14.99 && outs[0].avg_latency_ms < 15.01);
    CHECK(outs[0].last_seen == 2000);
  }

  /* Reverse direction: get_topo_edges_to */
  auto ins = net_db_get_topo_edges_to(db, b);
  CHECK(ins.size() == 1);
}

static void test_topo_batched_path_count(sqlite3 *db) {
  /* Regression for the post-C audit bug: path_count was hardcoded to 1
     in the upsert SQL regardless of what the caller passed.  After the
     fix, an upsert with NetTopoNode.path_count = 50 must add 50 to the
     stored count, not 1.  This is the bug that broke ORDER BY
     path_count DESC in --topo-export. */
  uint32_t ip = ip_to_u32("198.51.100.1");

  NetTopoNode batch_a{};
  batch_a.ip_u32     = ip;
  batch_a.path_count = 50;       /* 50 traces visited in batch A */
  batch_a.last_seen  = 7000;
  CHECK(net_db_upsert_topo_node(db, batch_a) == 0);

  NetTopoNode got{};
  CHECK(net_db_get_topo_node(db, ip, &got));
  CHECK(got.path_count == 50);   /* not 1 */

  NetTopoNode batch_b{};
  batch_b.ip_u32     = ip;
  batch_b.path_count = 30;       /* 30 traces in batch B */
  batch_b.last_seen  = 8000;
  CHECK(net_db_upsert_topo_node(db, batch_b) == 0);

  CHECK(net_db_get_topo_node(db, ip, &got));
  CHECK(got.path_count == 80);   /* 50 + 30, not 50 + 1 */
}

static void test_topo_edge_batched_running_mean(sqlite3 *db) {
  /* The running-mean formula must weight by the BATCH size, not assume
     each upsert is one sample.  Insert batch A with 2 samples averaging
     10ms, then batch B with 10 samples averaging 50ms.  Expected merged
     mean: (2*10 + 10*50) / 12 = 520/12 = 43.33ms. */
  uint32_t a = ip_to_u32("198.51.100.2");
  uint32_t b = ip_to_u32("198.51.100.3");

  NetTopoEdge batch_a{};
  batch_a.from_u32       = a;
  batch_a.to_u32         = b;
  batch_a.avg_latency_ms = 10.0;
  batch_a.path_count     = 2;
  batch_a.last_seen      = 7000;
  CHECK(net_db_upsert_topo_edge(db, batch_a) == 0);

  NetTopoEdge batch_b{};
  batch_b.from_u32       = a;
  batch_b.to_u32         = b;
  batch_b.avg_latency_ms = 50.0;
  batch_b.path_count     = 10;
  batch_b.last_seen      = 8000;
  CHECK(net_db_upsert_topo_edge(db, batch_b) == 0);

  auto outs = net_db_get_topo_edges_from(db, a);
  CHECK(outs.size() == 1);
  if (!outs.empty()) {
    CHECK(outs[0].path_count == 12);  /* 2 + 10 */
    /* 43.333... ms — within float tolerance */
    CHECK(outs[0].avg_latency_ms > 43.32 && outs[0].avg_latency_ms < 43.34);
  }
}

static void test_topo_edge_null_sample_keeps_prior_average(sqlite3 *db) {
  /* Send an edge with avg_latency_ms=0 (signals NULL via the >0 gate
     in the helper).  Prior average must stay put. */
  uint32_t a = ip_to_u32("10.0.0.1");
  uint32_t b = ip_to_u32("10.0.0.2");

  NetTopoEdge null_sample{};
  null_sample.from_u32       = a;
  null_sample.to_u32         = b;
  null_sample.avg_latency_ms = 0.0;  /* no sample */
  null_sample.last_seen      = 3000;
  CHECK(net_db_upsert_topo_edge(db, null_sample) == 0);

  auto outs = net_db_get_topo_edges_from(db, a);
  CHECK(outs.size() == 1);
  if (!outs.empty()) {
    /* Average stays at the previously-computed 15.0 */
    CHECK(outs[0].avg_latency_ms > 14.99 && outs[0].avg_latency_ms < 15.01);
    CHECK(outs[0].path_count == 3);  /* but count still bumped */
  }
}

static void test_high_ip_topo_roundtrip(sqlite3 *db) {
  /* Same uint32-as-int64 round-trip check as fingerprints. */
  uint32_t hi = ip_to_u32("220.10.20.30");
  CHECK(hi > 0x80000000u);
  NetTopoNode n{};
  n.ip_u32    = hi;
  n.asn       = 4294967290u;  /* deliberately above INT_MAX */
  n.last_seen = 4000;
  CHECK(net_db_upsert_topo_node(db, n) == 0);

  NetTopoNode got{};
  CHECK(net_db_get_topo_node(db, hi, &got));
  CHECK(got.ip_u32 == hi);
  CHECK(got.asn == 4294967290u);
}

int main() {
  std::string path = "/tmp/kmap_topo_test_" +
                     std::to_string(static_cast<long>(std::time(nullptr))) +
                     ".db";
  std::remove(path.c_str());

  sqlite3 *db = net_db_open(path);
  if (!db) {
    std::fprintf(stderr, "FATAL: net_db_open(%s) returned nullptr\n",
                 path.c_str());
    return 2;
  }

  test_intern_dedups(db);
  test_topo_node_upsert_idempotent(db);
  test_topo_node_partial_reobservation_keeps_data(db);
  test_topo_edge_upsert_and_running_mean(db);
  test_topo_edge_null_sample_keeps_prior_average(db);
  test_topo_batched_path_count(db);
  test_topo_edge_batched_running_mean(db);
  test_high_ip_topo_roundtrip(db);

  net_db_close(db);
  std::remove(path.c_str());

  if (g_failures == 0) {
    std::printf("net_db_topo_test: ALL PASS\n");
    return 0;
  } else {
    std::printf("net_db_topo_test: %d FAIL\n", g_failures);
    return 1;
  }
}
