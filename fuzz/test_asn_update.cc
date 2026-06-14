/* Focused regression test for net_db_update_asn data preservation.
 * Build (from fuzz/):
 *   g++ -O2 -std=gnu++17 -I.. test_asn_update.cc ../net_db.cc sqlite3_win.o -o test_asn_update.exe
 */
#include "net_db.h"
#include "sqlite/sqlite3.h"
#include <cstdio>
#include <string>

static std::string read_col(sqlite3 *db, const char *col, const char *ip) {
  std::string out = "<null>";
  std::string sql = std::string("SELECT ") + col + " FROM hosts WHERE ip=?";
  sqlite3_stmt *st = nullptr;
  if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) return "<err>";
  sqlite3_bind_text(st, 1, ip, -1, SQLITE_TRANSIENT);
  if (sqlite3_step(st) == SQLITE_ROW) {
    const unsigned char *t = sqlite3_column_text(st, 0);
    out = t ? std::string((const char *)t) : "<null>";
  }
  sqlite3_finalize(st);
  return out;
}

int main() {
  remove("./_asn_test.db");
  sqlite3 *db = net_db_open("./_asn_test.db");
  if (!db) { printf("FAIL: open\n"); return 1; }

  const char *ip = "203.0.113.7";
  uint32_t ipu = (203u<<24)|(0u<<16)|(113u<<8)|7u;
  net_db_insert_host(db, ipu, 443, "tcp", 1000);

  /* First enrichment: full ASN result. */
  net_db_update_asn(db, ip, 64512, "EXAMPLE-AS", "US", "203.0.113.0/24", "arin", "");
  std::string name1 = read_col(db, "as_name", ip);
  std::string cc1   = read_col(db, "country", ip);
  std::string bgp1  = read_col(db, "bgp_prefix", ip);

  /* Re-scan: origin query succeeds (asn>0, country/bgp present) but the
     separate AS-name query failed this time -> as_name empty. */
  net_db_update_asn(db, ip, 64512, "", "US", "203.0.113.0/24", "", "");
  std::string name2 = read_col(db, "as_name", ip);

  /* Re-scan 2: only asn present, country/bgp also empty (partial). */
  net_db_update_asn(db, ip, 64512, "", "", "", "", "");
  std::string name3 = read_col(db, "as_name", ip);
  std::string cc3   = read_col(db, "country", ip);
  std::string bgp3  = read_col(db, "bgp_prefix", ip);

  net_db_close(db);
  remove("./_asn_test.db");

  int fail = 0;
  printf("after first enrich:  as_name=%s country=%s bgp=%s\n", name1.c_str(), cc1.c_str(), bgp1.c_str());
  printf("after empty as_name: as_name=%s  (want EXAMPLE-AS)\n", name2.c_str());
  printf("after all-empty:     as_name=%s country=%s bgp=%s  (want EXAMPLE-AS/US/203.0.113.0/24)\n",
         name3.c_str(), cc3.c_str(), bgp3.c_str());

  if (name1 != "EXAMPLE-AS") { printf("FAIL: first enrich didn't store as_name\n"); fail++; }
  if (name2 != "EXAMPLE-AS") { printf("FAIL: as_name WIPED by empty re-lookup\n"); fail++; }
  if (name3 != "EXAMPLE-AS") { printf("FAIL: as_name WIPED by all-empty re-lookup\n"); fail++; }
  if (cc3   != "US")         { printf("FAIL: country WIPED by all-empty re-lookup\n"); fail++; }
  if (bgp3  != "203.0.113.0/24") { printf("FAIL: bgp_prefix WIPED by all-empty re-lookup\n"); fail++; }

  printf("\nasn-update test: %s\n", fail == 0 ? "PASS" : "FAIL");
  return fail == 0 ? 0 : 1;
}
