/* test_netquery.cc -- LIVE test of net_query.cc's SQL filter construction.
 *
 * Copies build_filter/bind_filter/parse_cidr/shards_for_cidr/max_cvss_from_json
 * VERBATIM from net_query.cc and runs them against a real in-memory sqlite DB.
 * Verifies (a) filter correctness, (b) SQL-injection resistance -- malicious
 * filter strings must be treated as literal LIKE values, never break out of
 * the parameterized query, and (c) CIDR math.
 *
 * Build (from fuzz/):
 *   gcc -O1 -c ../sqlite/sqlite3.c -o sqlite3_win.o   # if not already built
 *   g++ -O2 -std=gnu++17 -I.. test_netquery.cc sqlite3_win.o -o test_netquery.exe
 */
#include "sqlite/sqlite3.h"
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cctype>

#define NET_SHARD_COUNT 32

static int fails = 0, passes = 0;
#define CHECK(cond, msg) do { if (cond) { passes++; } \
  else { printf("  FAIL: %s\n", msg); fails++; } } while (0)

/* ---- helpers (verbatim / faithful) ---- */
static std::string str_lower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c){ return static_cast<char>(tolower(c)); });
  return r;
}
static uint32_t ip_to_u32(const char *ip_str) {  /* from net_db.cc */
  unsigned int a, b, c, d;
  if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
  if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
  return (a << 24) | (b << 16) | (c << 8) | d;
}

/* ===== VERBATIM from net_query.cc ===== */
struct CidrRange { uint32_t network; uint32_t mask; bool valid; };
static CidrRange parse_cidr(const char *cidr) {
  CidrRange r{}; r.valid = false;
  if (!cidr || !cidr[0]) return r;
  char buf[64]; size_t slen = strlen(cidr);
  if (slen >= sizeof(buf)) return r;
  memcpy(buf, cidr, slen + 1);
  char *slash = strchr(buf, '/'); int prefix_len = 32;
  if (slash) {
    /* Strict prefix parse -- mirrors net_query.cc parse_cidr. atoi() would
       silently turn "/abc" or "/" into prefix 0 (mask 0 => match every IP),
       so reject non-numeric / empty / trailing-junk prefixes. */
    *slash = '\0';
    const char *pp = slash + 1;
    if (*pp == '\0') return r;
    char *endp = nullptr;
    long pv = strtol(pp, &endp, 10);
    if (endp == pp || *endp != '\0') return r;
    if (pv < 0 || pv > 32) return r;
    prefix_len = static_cast<int>(pv);
  }
  uint32_t ip = ip_to_u32(buf);
  if (ip == 0 && strcmp(buf, "0.0.0.0") != 0) return r;
  if (prefix_len == 0) r.mask = 0;
  else r.mask = 0xFFFFFFFFU << (32 - prefix_len);
  r.network = ip & r.mask; r.valid = true; return r;
}
static bool ip_in_cidr(uint32_t ip, const CidrRange &cidr) {
  return (ip & cidr.mask) == cidr.network;
}
static std::vector<int> shards_for_cidr(const CidrRange &cidr) {
  std::vector<int> shards;
  for (int i = 0; i < NET_SHARD_COUNT; i++) {
    uint32_t shard_start = static_cast<uint32_t>(i) << 27;
    uint32_t shard_end   = shard_start | 0x07FFFFFFU;
    uint32_t cidr_end = cidr.network | ~cidr.mask;
    if (cidr.network <= shard_end && shard_start <= cidr_end) shards.push_back(i);
  }
  return shards;
}
struct QueryFilter {
  std::string where_clause;
  enum BindType { BTEXT, BINT };
  struct BindVal { BindType type; std::string text_val; int int_val; };
  std::vector<BindVal> binds;
};
/* kev_only/min_epss default to off so the many pre-existing call sites below
   stay terse; the new cases pass them explicitly. */
static QueryFilter build_filter(int port, const char *service,
                                const char *cve, float min_cvss,
                                const char *web_title, const char *web_server,
                                int asn, const char *country,
                                bool kev_only = false, float min_epss = 0.0f) {
  QueryFilter f; std::vector<std::string> conditions;
  if (port > 0) { conditions.push_back("port = ?");
                  f.binds.push_back({QueryFilter::BINT, "", port}); }
  if (service && service[0]) { conditions.push_back("LOWER(service) LIKE ?");
    f.binds.push_back({QueryFilter::BTEXT, "%" + str_lower(service) + "%", 0}); }
  if (cve && cve[0]) { conditions.push_back("cves LIKE ?");
    f.binds.push_back({QueryFilter::BTEXT, "%" + std::string(cve) + "%", 0}); }
  if (min_cvss > 0.0f)
    conditions.push_back("cves IS NOT NULL AND cves != '' AND cves != '[]'");
  if (kev_only)
    conditions.push_back("cves LIKE '%\"kev\":1%'");
  if (min_epss > 0.0f)
    conditions.push_back("cves IS NOT NULL AND cves != '' AND cves != '[]'");
  if (web_title && web_title[0]) { conditions.push_back("LOWER(web_title) LIKE ?");
    f.binds.push_back({QueryFilter::BTEXT, "%" + str_lower(web_title) + "%", 0}); }
  if (web_server && web_server[0]) { conditions.push_back("LOWER(web_server) LIKE ?");
    f.binds.push_back({QueryFilter::BTEXT, "%" + str_lower(web_server) + "%", 0}); }
  if (asn > 0) { conditions.push_back("asn = ?");
                 f.binds.push_back({QueryFilter::BINT, "", asn}); }
  if (country && country[0]) {
    std::string cc = country;
    std::transform(cc.begin(), cc.end(), cc.begin(),
                   [](unsigned char c){ return static_cast<char>(toupper(c)); });
    conditions.push_back("UPPER(country) = ?");
    f.binds.push_back({QueryFilter::BTEXT, cc, 0});
  }
  if (conditions.empty()) f.where_clause = "1=1";
  else { std::ostringstream oss;
    for (size_t i = 0; i < conditions.size(); i++) {
      if (i > 0) oss << " AND "; oss << conditions[i]; }
    f.where_clause = oss.str(); }
  return f;
}
static void bind_filter(sqlite3_stmt *stmt, const QueryFilter &f) {
  int idx = 1;
  for (const auto &b : f.binds) {
    switch (b.type) {
      case QueryFilter::BTEXT:
        sqlite3_bind_text(stmt, idx, b.text_val.c_str(), -1, SQLITE_TRANSIENT); break;
      case QueryFilter::BINT:
        sqlite3_bind_int(stmt, idx, b.int_val); break;
    }
    idx++;
  }
}
/* max_epss_from_json / json_has_kev: VERBATIM from net_query.cc -- the
   post-filter logic for --nq-min-epss / --nq-kev applied per row over the JSON
   cves column. */
static float max_epss_from_json(const std::string &cves_json) {
  float max_epss = -1.0f;
  size_t pos = 0;
  while (true) {
    pos = cves_json.find("\"epss\":", pos);
    if (pos == std::string::npos) break;
    pos += 7;
    while (pos < cves_json.size() && cves_json[pos] == ' ') pos++;
    size_t end = pos;
    while (end < cves_json.size() &&
           (isdigit(static_cast<unsigned char>(cves_json[end])) ||
            cves_json[end] == '.'))
      end++;
    if (end > pos) {
      float v = static_cast<float>(atof(cves_json.substr(pos, end - pos).c_str()));
      if (v > max_epss) max_epss = v;
    }
    pos = end;
  }
  return max_epss;
}
static bool json_has_kev(const std::string &cves_json) {
  return cves_json.find("\"kev\":1") != std::string::npos;
}
/* ===== end verbatim ===== */

static sqlite3 *g_db;
/* Run SELECT ip||':'||port with the filter; return matched "ip:port" rows. */
static std::vector<std::string> run_query(const QueryFilter &f) {
  std::vector<std::string> out;
  std::string sql = "SELECT ip, port FROM hosts WHERE " + f.where_clause;
  sqlite3_stmt *st = nullptr;
  if (sqlite3_prepare_v2(g_db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
    printf("  [prepare failed: %s]\n", sqlite3_errmsg(g_db)); return out; }
  bind_filter(st, f);
  while (sqlite3_step(st) == SQLITE_ROW) {
    out.push_back(std::string((const char*)sqlite3_column_text(st,0)) + ":" +
                  std::to_string(sqlite3_column_int(st,1)));
  }
  sqlite3_finalize(st);
  return out;
}
static int table_exists() {
  sqlite3_stmt *st = nullptr; int n = -1;
  if (sqlite3_prepare_v2(g_db,
      "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='hosts'",
      -1, &st, nullptr) == SQLITE_OK) {
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
  }
  return n;
}
static bool has(const std::vector<std::string>&v, const char*s){
  for (auto&x:v) if (x==s) return true; return false; }

int main() {
  if (sqlite3_open(":memory:", &g_db) != SQLITE_OK) { printf("open fail\n"); return 2; }
  sqlite3_exec(g_db,
    "CREATE TABLE hosts(ip TEXT, port INT, service TEXT, cves TEXT, "
    "web_title TEXT, web_server TEXT, asn INT, country TEXT);"
    "INSERT INTO hosts VALUES('1.1.1.1',22,'ssh','',NULL,NULL,0,'');"
    "INSERT INTO hosts VALUES('2.2.2.2',443,'https','','Login Page','nginx',13335,'US');"
    "INSERT INTO hosts VALUES('3.3.3.3',80,'http','',NULL,NULL,0,'DE');"
    /* 4.4.4.4 carries KEV + EPSS in the exact shape net_enrich.cc::cves_to_json
       emits, so the EPSS/KEV cases reuse it without changing any row counts. */
    "INSERT INTO hosts VALUES('4.4.4.4',3306,'mysql',"
    "'[{\"id\":\"CVE-2024-1\",\"cvss\":9.1,\"epss\":0.9999,\"kev\":1,\"ransomware\":1}]',"
    "NULL,NULL,0,'');",
    nullptr, nullptr, nullptr);

  /* ---- correctness ---- */
  CHECK(run_query(build_filter(0,"ssh",0,0,0,0,0,0)) == std::vector<std::string>{"1.1.1.1:22"},
        "service=ssh -> exact ssh row");
  { auto r = run_query(build_filter(0,"http",0,0,0,0,0,0));  /* LIKE %http% */
    CHECK(r.size()==2 && has(r,"2.2.2.2:443") && has(r,"3.3.3.3:80"),
          "service LIKE %http% matches http + https"); }
  CHECK(run_query(build_filter(443,0,0,0,0,0,0,0)) == std::vector<std::string>{"2.2.2.2:443"},
        "port=443 filter");
  CHECK(run_query(build_filter(0,0,0,0,0,0,0,"us")) == std::vector<std::string>{"2.2.2.2:443"},
        "country=us (case-insensitive) -> US row");
  CHECK(run_query(build_filter(0,0,0,0,0,0,13335,0)) == std::vector<std::string>{"2.2.2.2:443"},
        "asn=13335 filter");
  CHECK(run_query(build_filter(0,0,0,0,"login",0,0,0)) == std::vector<std::string>{"2.2.2.2:443"},
        "web_title LIKE %login% (case-insensitive)");
  CHECK(run_query(build_filter(0,0,0,1.0f,0,0,0,0)) == std::vector<std::string>{"4.4.4.4:3306"},
        "min_cvss>0 prefilters to rows with CVE data");

  /* ---- EPSS / CISA-KEV (--nq-kev / --nq-min-epss) ---- */
  /* KEV SQL pre-filter: only the row whose JSON carries "kev":1. */
  CHECK(run_query(build_filter(0,0,0,0,0,0,0,0,/*kev_only=*/true)) ==
            std::vector<std::string>{"4.4.4.4:3306"},
        "kev_only -> only the KEV-flagged row");
  /* A row with no cves at all (1.1.1.1) must never match the KEV pre-filter. */
  CHECK(!has(run_query(build_filter(0,0,0,0,0,0,0,0,true)), "1.1.1.1:22"),
        "kev_only excludes rows without CVE data");
  /* EPSS post-filter math over the JSON array. */
  CHECK(max_epss_from_json(
          "[{\"id\":\"a\",\"cvss\":9.8,\"epss\":0.9999,\"kev\":1,\"ransomware\":1}]")
          > 0.999f,
        "max_epss_from_json reads the epss value");
  CHECK(max_epss_from_json("[{\"id\":\"a\",\"cvss\":9.1}]") < 0.0f,
        "max_epss_from_json -> -1 when no epss present");
  { /* picks the maximum across multiple entries */
    float m = max_epss_from_json(
      "[{\"id\":\"a\",\"epss\":0.10},{\"id\":\"b\",\"epss\":0.87},{\"id\":\"c\",\"epss\":0.42}]");
    CHECK(m > 0.86f && m < 0.88f, "max_epss_from_json picks the max of several"); }
  CHECK(json_has_kev("[{\"id\":\"a\",\"kev\":1}]"), "json_has_kev true");
  CHECK(!json_has_kev("[{\"id\":\"a\",\"cvss\":9.1}]"), "json_has_kev false");
  /* "kev":0 (catalog-cleared) must not count as KEV. */
  CHECK(!json_has_kev("[{\"id\":\"a\",\"kev\":0}]"), "json_has_kev ignores kev:0");

  /* ---- SQL injection: payloads must be literal, returning 0 rows ---- */
  CHECK(run_query(build_filter(0,"' OR '1'='1",0,0,0,0,0,0)).empty(),
        "injection: service=\"' OR '1'='1\" matches nothing (not all rows)");
  CHECK(run_query(build_filter(0,"x%' OR 1=1 --",0,0,0,0,0,0)).empty(),
        "injection: tautology payload matches nothing");
  CHECK(run_query(build_filter(0,0,"'; DROP TABLE hosts; --",0,0,0,0,0)).empty(),
        "injection: DROP payload in cve filter matches nothing");
  CHECK(table_exists() == 1, "hosts table STILL EXISTS after DROP-payload query");
  CHECK(run_query(build_filter(0,0,0,0,"a'); DELETE FROM hosts; --",0,0,0)).empty(),
        "injection: DELETE payload in web_title matches nothing");
  { sqlite3_stmt*st=nullptr; int cnt=0;
    sqlite3_prepare_v2(g_db,"SELECT count(*) FROM hosts",-1,&st,nullptr);
    if (sqlite3_step(st)==SQLITE_ROW) cnt=sqlite3_column_int(st,0);
    sqlite3_finalize(st);
    CHECK(cnt==4, "all 4 rows still present (no injection deleted data)"); }

  /* ---- static: user string never appears in the SQL text ---- */
  { QueryFilter f = build_filter(0,"evil' OR 1=1 --",0,0,0,0,0,0);
    CHECK(f.where_clause.find("evil")==std::string::npos &&
          f.where_clause.find("OR 1=1")==std::string::npos &&
          f.where_clause=="LOWER(service) LIKE ?",
          "user filter value is bound, not concatenated into SQL"); }

  /* ---- CIDR math ---- */
  CidrRange c16 = parse_cidr("2.2.0.0/16");
  CHECK(c16.valid && c16.mask==0xFFFF0000U && c16.network==0x02020000U, "parse /16");
  CHECK(ip_in_cidr(ip_to_u32("2.2.2.2"), c16),  "2.2.2.2 in 2.2.0.0/16");
  CHECK(!ip_in_cidr(ip_to_u32("3.3.3.3"), c16), "3.3.3.3 not in 2.2.0.0/16");
  CidrRange c0 = parse_cidr("0.0.0.0/0");
  CHECK(c0.valid && c0.mask==0 && shards_for_cidr(c0).size()==NET_SHARD_COUNT,
        "/0 spans all shards");
  CidrRange c32 = parse_cidr("8.8.8.8/32");
  CHECK(c32.valid && c32.mask==0xFFFFFFFFU, "parse /32");
  CHECK(!parse_cidr("not-an-ip").valid,        "invalid CIDR rejected");
  CHECK(!parse_cidr("1.2.3.4/33").valid,       "prefix >32 rejected");
  /* Strict-prefix footguns: atoi() would turn these into a /0 match-all and
     silently return the entire dataset. The strict strtol parse must reject. */
  CHECK(!parse_cidr("1.2.3.4/abc").valid,      "non-numeric prefix rejected");
  CHECK(!parse_cidr("1.2.3.4/").valid,         "empty prefix rejected");
  CHECK(!parse_cidr("1.2.3.4/16x").valid,      "trailing junk after prefix rejected");
  CHECK(parse_cidr("1.2.3.4/0").valid && parse_cidr("1.2.3.4/0").mask==0,
        "explicit /0 still accepted");
  CHECK(shards_for_cidr(c16).size()==1,        "/16 maps to a single shard");

  printf("\nnet_query live test: %d passed, %d failed\n", passes, fails);
  sqlite3_close(g_db);
  return fails ? 1 : 0;
}
