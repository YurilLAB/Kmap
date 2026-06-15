/*
 * test_search.cc -- live test for net_db_search_fts (the --search FTS5 core).
 * Seeds enriched hosts, then asserts free-text + faceted FTS5 queries.
 *
 * Build (sqlite MUST be compiled with FTS5):
 *   gcc -O1 -DSQLITE_THREADSAFE=0 -DSQLITE_ENABLE_FTS5 -c sqlite/sqlite3.c -o /tmp/sqlite3_fts.o
 *   g++ -O2 -std=gnu++17 -DWIN32 -I. -Inbase fuzz/test_search.cc net_db.cc \
 *       /tmp/sqlite3_fts.o -lws2_32 -lbcrypt -o fuzz/test_search.exe && fuzz/test_search.exe
 */

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include "../net_db.h"

static int g_fail = 0;
static void ok(bool c, const char *m) { if (!c) { printf("  FAIL: %s\n", m); g_fail++; } }

static bool hit_has(const std::vector<NetSearchHit> &h, const char *ip) {
  for (const auto &x : h) if (x.ip == ip) return true;
  return false;
}

static void seed(sqlite3 *db, const char *ip, uint32_t ipu, int port,
                 const char *svc, const char *ver, const char *cpe,
                 const char *title, const char *asn, const char *cc,
                 const char *cloud) {
  net_db_insert_host(db, ipu, port, "tcp", 1718000000);
  net_db_update_enrichment(db, ip, port, svc, ver, "[]", title, "srv", "{}", "[]",
                           nullptr, nullptr, nullptr, nullptr, cpe);
  net_db_update_asn(db, ip, 12345, asn, cc, "1.0.0.0/24", "arin", "NA");
  if (cloud && cloud[0]) net_db_update_cloud(db, ip, cloud, "", "");
}

int main(void) {
  const char *path = "search_test.sqlite";
  remove(path);
  sqlite3 *db = net_db_open(path);
  if (!db) { printf("cannot open db\n"); return 1; }

  seed(db, "1.0.0.1", 0x01000001, 443, "https", "nginx 1.18.0",
       "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", "Welcome Home",
       "CLOUDFLARENET", "US", "cloudflare");
  seed(db, "1.0.0.2", 0x01000002, 80, "http", "Apache httpd 2.4.41",
       "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*", "Apache2 Default Page",
       "HETZNER", "DE", "");
  seed(db, "1.0.0.3", 0x01000003, 22, "ssh", "OpenSSH 8.2",
       "cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*", "", "GOOGLE", "US", "");

  std::string err;
  auto search = [&](const char *q) {
    err.clear();
    return net_db_search_fts(db, q, 100, &err);
  };

  /* free-text term hits the right host */
  { auto h = search("nginx");  ok(h.size() == 1 && hit_has(h, "1.0.0.1"), "free-text nginx -> 1.0.0.1"); }
  { auto h = search("apache"); ok(h.size() == 1 && hit_has(h, "1.0.0.2"), "free-text apache -> 1.0.0.2"); }
  { auto h = search("openssh");ok(h.size() == 1 && hit_has(h, "1.0.0.3"), "free-text openssh -> 1.0.0.3"); }

  /* faceted column filter */
  { auto h = search("country:US");
    ok(h.size() == 2 && hit_has(h, "1.0.0.1") && hit_has(h, "1.0.0.3"), "facet country:US -> 2"); }
  { auto h = search("cloud:cloudflare");
    ok(h.size() == 1 && hit_has(h, "1.0.0.1"), "facet cloud:cloudflare -> 1.0.0.1"); }
  { auto h = search("service:https"); ok(h.size() == 1 && hit_has(h, "1.0.0.1"), "facet service:https"); }

  /* boolean combination */
  { auto h = search("country:US AND service:ssh");
    ok(h.size() == 1 && hit_has(h, "1.0.0.3"), "US AND ssh -> 1.0.0.3"); }
  { auto h = search("country:US NOT service:ssh");
    ok(h.size() == 1 && hit_has(h, "1.0.0.1"), "US NOT ssh -> 1.0.0.1"); }

  /* web title term */
  { auto h = search("Welcome"); ok(h.size() == 1 && hit_has(h, "1.0.0.1"), "title term Welcome"); }

  /* the hit carries the structured fields back */
  { auto h = search("nginx");
    ok(!h.empty() && h[0].port == 443 && h[0].country == "US" &&
       h[0].cloud_provider == "cloudflare" && h[0].cpe.find("nginx") != std::string::npos,
       "hit carries port/country/cloud/cpe"); }

  /* no match + empty/invalid query error paths */
  { auto h = search("zzznomatch12345"); ok(h.empty(), "no-match -> empty"); }
  { auto h = search("");  ok(h.empty() && !err.empty(), "empty query -> err"); }
  { auto h = search("\"unclosed"); ok(h.empty() && !err.empty(), "bad FTS grammar -> err, no crash"); }

  net_db_close(db);
  remove(path);
  std::string wal = std::string(path) + "-wal", shm = std::string(path) + "-shm";
  remove(wal.c_str()); remove(shm.c_str());

  printf("\n%s\n", g_fail == 0 ? "search test: ALL PASS" : "search test: FAILURES");
  return g_fail == 0 ? 0 : 1;
}
