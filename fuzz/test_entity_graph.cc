/*
 * test_entity_graph.cc -- live integration test for entity_graph.cc.
 *
 * Seeds two shard DBs (a seed host + a second host sharing its certificate),
 * runs the REAL entity_graph_build over them, and asserts the assembled nodes
 * and edges + the cohort expansion.
 *
 * Build (links the real assembler + net_db + sqlite):
 *   gcc -O1 -c sqlite/sqlite3.c -o /tmp/sqlite3.o
 *   g++ -O2 -std=gnu++17 -DWIN32 -I. -Inbase fuzz/test_entity_graph.cc \
 *       entity_graph.cc net_db.cc /tmp/sqlite3.o -lws2_32 -lbcrypt \
 *       -o fuzz/test_entity_graph.exe && fuzz/test_entity_graph.exe
 */

#include <cstdio>
#include <cstdint>
#include <string>
#include <map>
#include <vector>

#include "../entity_graph.h"
#include "../net_db.h"

#ifdef _WIN32
#include <direct.h>
#define MKDIR(d) _mkdir(d)
#else
#include <sys/stat.h>
#define MKDIR(d) mkdir(d, 0755)
#endif

static int g_fail = 0;
static void ok(bool c, const char *m) { if (!c) { printf("  FAIL: %s\n", m); g_fail++; } }

static bool has_node(const std::map<std::string, EgNode> &n, const std::string &id) {
  return n.find(id) != n.end();
}
static bool has_edge(const std::vector<EgEdge> &e, const std::string &f,
                     const std::string &t, const std::string &l) {
  for (const EgEdge &x : e)
    if (x.from == f && x.to == t && x.label == l) return true;
  return false;
}

static void seed_host(const char *dir, const char *ip, uint32_t ipu,
                      uint32_t asn, const char *as_name, const char *country,
                      const char *sha, const char *cn) {
  std::string sp = net_shard_path(dir, net_shard_index(ipu));
  sqlite3 *db = net_db_open(sp.c_str());
  if (!db) { printf("  FAIL: cannot open shard %s\n", sp.c_str()); g_fail++; return; }
  net_db_insert_host(db, ipu, 443, "tcp", 1718000000);
  net_db_update_asn(db, ip, asn, as_name, country, "203.0.113.0/24",
                    "arin", "North America");
  net_db_update_tls(db, ip, 443, cn, "Let's Encrypt",
                    "[\"www.example.com\"]", "2026-09-01", 0, "TLSv1.3", sha);
  net_db_insert_fingerprint(db, ipu, 443, "tls_sha256", sha, 1718000000);
  net_db_insert_fingerprint(db, ipu, 443, "tls_subject_cn", cn, 1718000000);
  net_db_insert_fingerprint(db, ipu, 443, "tls_san", "www.example.com", 1718000000);
  net_db_insert_fingerprint(db, ipu, 443, "hostname", "host.example.com", 1718000000);
  net_db_close(db);
}

int main(void) {
  const char *dir = "eg_test_data";
  MKDIR(dir);

  const char *SEED = "203.0.113.10";   /* TEST-NET-3 */
  const char *PEER = "198.51.100.20";  /* TEST-NET-2 (likely a different shard) */
  const char *SHA  = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
  uint32_t seed_u = ip_to_u32(SEED), peer_u = ip_to_u32(PEER);

  seed_host(dir, SEED, seed_u, 13335, "CLOUDFLARENET", "US", SHA, "example.com");
  /* Peer shares the SAME cert SHA -> must appear in the depth-1 cohort. */
  seed_host(dir, PEER, peer_u, 24940, "HETZNER", "DE", SHA, "peer.example.com");

  /* ---- depth 0: seed subgraph only ---- */
  {
    std::map<std::string, EgNode> nodes; std::vector<EgEdge> edges; size_t coh = 0;
    int rc = entity_graph_build(dir, SEED, 0, nodes, edges, &coh);
    ok(rc == 0, "depth0 build ok");
    ok(coh == 0, "depth0 no cohort");
    ok(has_node(nodes, "ip:203.0.113.10"), "depth0 seed ip node");
    ok(has_node(nodes, "asn:13335"),       "depth0 asn node");
    ok(has_node(nodes, "org:CLOUDFLARENET"),"depth0 org node");
    ok(has_node(nodes, "country:US"),      "depth0 country node");
    ok(has_node(nodes, std::string("cert:") + SHA), "depth0 cert node");
    ok(has_node(nodes, "domain:example.com"),       "depth0 cert-CN domain node");
    ok(has_node(nodes, "domain:www.example.com"),   "depth0 SAN domain node");
    ok(has_node(nodes, "domain:host.example.com"),  "depth0 PTR domain node");
    ok(!has_node(nodes, "ip:198.51.100.20"), "depth0 peer NOT present");

    ok(has_edge(edges, "ip:203.0.113.10", "asn:13335", "announced_by"), "edge ip->asn");
    ok(has_edge(edges, "asn:13335", "org:CLOUDFLARENET", "operated_by"), "edge asn->org");
    ok(has_edge(edges, "asn:13335", "country:US", "registered_in"),      "edge asn->country");
    ok(has_edge(edges, "ip:203.0.113.10", std::string("cert:") + SHA, "presents"), "edge ip->cert");
    ok(has_edge(edges, "domain:example.com", std::string("cert:") + SHA, "certified_by"), "edge domain->cert");
    ok(has_edge(edges, "ip:203.0.113.10", "domain:www.example.com", "serves"), "edge ip->san domain");
    ok(has_edge(edges, "ip:203.0.113.10", "domain:host.example.com", "resolves_to"), "edge ip->ptr domain");
  }

  /* ---- depth 1: peer sharing the cert is pulled into the cohort ---- */
  {
    std::map<std::string, EgNode> nodes; std::vector<EgEdge> edges; size_t coh = 0;
    int rc = entity_graph_build(dir, SEED, 1, nodes, edges, &coh);
    ok(rc == 0, "depth1 build ok");
    ok(coh >= 1, "depth1 cohort >= 1");
    ok(has_node(nodes, "ip:198.51.100.20"), "depth1 peer ip present (shared cert)");
    ok(has_node(nodes, "asn:24940"),  "depth1 peer asn present");
    ok(has_node(nodes, "org:HETZNER"),"depth1 peer org present");
    ok(has_edge(edges, "ip:198.51.100.20", std::string("cert:") + SHA, "presents"),
       "depth1 peer presents shared cert");
  }

  /* ---- bad seed ---- */
  {
    std::map<std::string, EgNode> nodes; std::vector<EgEdge> edges; size_t coh = 0;
    ok(entity_graph_build(dir, "not-an-ip", 1, nodes, edges, &coh) == -1, "bad seed -> -1");
    std::map<std::string, EgNode> n2; std::vector<EgEdge> e2; size_t c2 = 0;
    ok(entity_graph_build(dir, "192.0.2.250", 0, n2, e2, &c2) == -2, "unknown ip -> -2 (no data)");
  }

  /* ---- emit smoke: each format writes non-empty, well-formed-ish output ---- */
  {
    std::map<std::string, EgNode> nodes; std::vector<EgEdge> edges; size_t coh = 0;
    entity_graph_build(dir, SEED, 1, nodes, edges, &coh);
    for (const char *fmt : {"json", "dot", "text"}) {
      const char *path = "eg_emit_tmp.out";
      FILE *f = fopen(path, "w");
      if (f) { entity_graph_emit(f, fmt, SEED, 1, coh, nodes, edges); fclose(f); }
      f = fopen(path, "rb");
      std::string content; char b[4096]; size_t n;
      if (f) { while ((n = fread(b, 1, sizeof(b), f)) > 0) content.append(b, n); fclose(f); }
      remove(path);
      char msg[64]; snprintf(msg, sizeof(msg), "emit %s non-empty", fmt);
      ok(content.size() > 50, msg);
      ok(content.find("203.0.113.10") != std::string::npos,
         (std::string("emit ") + fmt + " contains seed").c_str());
    }
  }

  /* cleanup */
  remove(net_shard_path(dir, net_shard_index(seed_u)).c_str());
  remove(net_shard_path(dir, net_shard_index(peer_u)).c_str());

  printf("\n%s\n", g_fail == 0 ? "entity-graph test: ALL PASS" : "entity-graph test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
