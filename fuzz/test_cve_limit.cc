/*
 * test_cve_limit.cc -- proves the CVE-lookup SQL LIMIT must be the 2000-row
 * backstop (with the applicable-cap applied in C++ AFTER version filtering),
 * not LIMIT 100 in SQL.
 *
 * Both net_enrich.cc::lookup_cves and net_enrich_async.cc::a_lookup_cves order
 * candidate rows by CVSS desc, then version-filter in C++ and keep up to 100
 * APPLICABLE matches. If the SQL caps at 100 rows, the 100 highest-CVSS rows
 * are taken BEFORE version filtering -- so an older CVE that genuinely applies
 * to the detected version but ranks beyond the top-100-by-CVSS for a busy
 * product is dropped. The async copy used LIMIT 100 and had exactly this gap;
 * this pins that the 2000-row scan finds such a CVE while LIMIT 100 misses it.
 *
 * Build (Win):  gcc -O1 -c ../sqlite/sqlite3.c -o sqlite3_win.o   (one-time)
 *   g++ -O2 -std=gnu++17 -I.. test_cve_limit.cc sqlite3_win.o -o test_cve_limit.exe
 * Build (CI):   g++ $CXXFLAGS -I. fuzz/test_cve_limit.cc sqlite3.o -o test_cve_limit
 */
#include "sqlite/sqlite3.h"
#include <cstdio>
#include <string>
#include <vector>

/* Minimal dotted-numeric version compare, same semantics as the enrich
   ver_cmp helpers (parse leading digits per '.'-token, missing parts = 0). */
static std::vector<int> parse_ver(const std::string &s) {
  std::vector<int> p; std::string cur;
  for (char c : s + ".") {
    if (c == '.') { if (!cur.empty()) p.push_back(atoi(cur.c_str())); cur.clear(); }
    else if (c >= '0' && c <= '9') cur += c;
    else break;
  }
  return p;
}
static int ver_cmp(const std::string &a, const std::string &b) {
  auto va = parse_ver(a), vb = parse_ver(b);
  size_t n = va.size() > vb.size() ? va.size() : vb.size();
  for (size_t i = 0; i < n; i++) {
    int ai = i < va.size() ? va[i] : 0, bi = i < vb.size() ? vb[i] : 0;
    if (ai != bi) return ai < bi ? -1 : 1;
  }
  return 0;
}

/* Mirror of the enrich CVE lookup: order by cvss desc, version-filter in C++,
   keep up to `cap` applicable. `sql_limit` is the SQL row backstop under test. */
static std::vector<std::string> lookup(sqlite3 *db, const char *product,
                                       const std::string &det, int sql_limit, int cap) {
  std::vector<std::string> out;
  std::string sql = "SELECT cve_id, version_min, version_max FROM cves "
                    "WHERE product = ? AND cvss_score >= 0.0 "
                    "ORDER BY cvss_score DESC LIMIT " + std::to_string(sql_limit);
  sqlite3_stmt *st = nullptr;
  if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) return out;
  sqlite3_bind_text(st, 1, product, -1, SQLITE_TRANSIENT);
  while (sqlite3_step(st) == SQLITE_ROW) {
    auto col = [&](int c){ const unsigned char*p=sqlite3_column_text(st,c); return std::string(p?(const char*)p:""); };
    std::string id = col(0), vmin = col(1), vmax = col(2);
    /* Require a version bound: a row with neither bound has no version
       applicability and would match every version -- a false positive. Mirrors
       lookup_cves (net_enrich.cc) and run_cve_map (cve_map.cc). */
    if (vmin.empty() && vmax.empty()) continue;
    if (!vmin.empty() && ver_cmp(det, vmin) < 0) continue;
    if (!vmax.empty() && ver_cmp(det, vmax) > 0) continue;
    out.push_back(id);
    if ((int)out.size() >= cap) break;
  }
  sqlite3_finalize(st);
  return out;
}

int main(void) {
  printf("CVE-lookup SQL-LIMIT model test\n===============================\n");
  sqlite3 *db = nullptr;
  if (sqlite3_open(":memory:", &db) != SQLITE_OK) { printf("open fail\n"); return 1; }
  sqlite3_exec(db, "CREATE TABLE cves (cve_id TEXT, product TEXT, version_min TEXT, "
                   "version_max TEXT, cvss_score REAL)", nullptr, nullptr, nullptr);

  /* 120 high-CVSS rows for http_server that do NOT apply to detected 2.4
     (version_max 1.0), plus ONE low-CVSS row that DOES apply (2.0..3.0).
     Ordered by CVSS desc the applicable row ranks ~121 -- beyond a LIMIT 100. */
  sqlite3_exec(db, "BEGIN", nullptr, nullptr, nullptr);
  for (int i = 0; i < 120; i++) {
    char ins[256];
    snprintf(ins, sizeof(ins),
      "INSERT INTO cves VALUES('CVE-HIGH-%03d','http_server','','1.0',%f)",
      i, 9.9 - i * 0.001);
    sqlite3_exec(db, ins, nullptr, nullptr, nullptr);
  }
  sqlite3_exec(db,
    "INSERT INTO cves VALUES('CVE-MATCH','http_server','2.0','3.0',5.0)",
    nullptr, nullptr, nullptr);
  /* A high-CVSS row with NO version bounds (both empty) -- the description-
     keyword false-positive class. It must NOT match any detected version. */
  sqlite3_exec(db,
    "INSERT INTO cves VALUES('CVE-NOBOUND','http_server','','',9.8)",
    nullptr, nullptr, nullptr);
  sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);

  auto contains = [](const std::vector<std::string> &v, const char *id) {
    for (auto &s : v) if (s == id) return true; return false; };

  int fail = 0;
  /* Old async behavior: LIMIT 100 in SQL -> applicable low-CVSS CVE missed. */
  auto old_res = lookup(db, "http_server", "2.4", 100, 100);
  if (contains(old_res, "CVE-MATCH")) {
    printf("  (note) LIMIT 100 happened to include it -- weakening expected\n");
  } else {
    printf("  OK   LIMIT 100 MISSES the applicable beyond-top-100 CVE (the bug)\n");
  }
  /* Fixed behavior (= sync): LIMIT 2000 backstop + C++ cap -> found. */
  auto new_res = lookup(db, "http_server", "2.4", 2000, 100);
  if (!contains(new_res, "CVE-MATCH")) {
    printf("  FAIL LIMIT 2000 should find the applicable CVE but did not\n"); fail++;
  } else {
    printf("  OK   LIMIT 2000 + C++ cap FINDS the applicable CVE (the fix)\n");
  }
  /* And the fix must demonstrably differ from the bug on this data. */
  if (contains(old_res, "CVE-MATCH") == contains(new_res, "CVE-MATCH")) {
    printf("  FAIL fix did not change the outcome on the crafted data\n"); fail++;
  }

  /* The no-version-bound row must never match, at any SQL limit. */
  if (contains(new_res, "CVE-NOBOUND")) {
    printf("  FAIL bound-less CVE matched (false positive)\n"); fail++;
  } else {
    printf("  OK   bound-less CVE (no version_min/max) is correctly skipped\n");
  }

  sqlite3_close(db);
  printf("\n%s\n", fail == 0 ? "cve-limit test: ALL PASS" : "cve-limit test: FAILURES");
  return fail == 0 ? 0 : 1;
}
