/* net_db_fingerprint_test.cc -- End-to-end test of fingerprint helpers.
 *
 * Opens a temporary shard DB, exercises:
 *   - net_db_insert_fingerprint (insert + UPSERT refresh on repeat)
 *   - net_db_find_by_fingerprint (inverse lookup)
 *   - net_db_get_fingerprints_for_ip (forward lookup)
 *
 * Validates the bits a code-pattern test cannot: that the schema actually
 * creates the table, that the indexes are usable, that ip_u32 round-trips
 * cleanly through int64 binding for IPs above INT_MAX, and that the
 * (ip_u32, kind, value) primary key collapses duplicates correctly.
 *
 * Build:
 *   g++ -o net_db_fingerprint_test \
 *       tests/net_db_fingerprint_test.cc net_db.cc sqlite/sqlite3.o
 */

#include "../net_db.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <set>

static int g_failures = 0;

#define CHECK(expr) do { \
    if (!(expr)) { \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
      ++g_failures; \
    } \
  } while (0)

static void test_insert_and_find_back(sqlite3 *db) {
  /* Insert one fingerprint, look it up two ways, expect to get it back. */
  int rc = net_db_insert_fingerprint(db,
      ip_to_u32("10.0.0.1"), 443, "tls_sha256", "abc123", 1000);
  CHECK(rc == 0);

  auto by_fp = net_db_find_by_fingerprint(db, "tls_sha256", "abc123");
  CHECK(by_fp.size() == 1);
  if (!by_fp.empty()) {
    CHECK(by_fp[0].ip_u32 == ip_to_u32("10.0.0.1"));
    CHECK(by_fp[0].port == 443);
    CHECK(by_fp[0].kind == "tls_sha256");
    CHECK(by_fp[0].value == "abc123");
    CHECK(by_fp[0].observed_at == 1000);
  }

  auto by_ip = net_db_get_fingerprints_for_ip(db, "10.0.0.1");
  CHECK(by_ip.size() == 1);
}

static void test_upsert_refreshes_observed_at(sqlite3 *db) {
  /* Re-insert the same (ip, kind, value) with a newer timestamp.
     Should not create a duplicate row; should refresh observed_at. */
  int rc = net_db_insert_fingerprint(db,
      ip_to_u32("10.0.0.1"), 443, "tls_sha256", "abc123", 2000);
  CHECK(rc == 0);

  auto by_fp = net_db_find_by_fingerprint(db, "tls_sha256", "abc123");
  CHECK(by_fp.size() == 1);
  if (!by_fp.empty()) {
    CHECK(by_fp[0].observed_at == 2000);
  }
}

static void test_inverse_lookup_finds_cohort(sqlite3 *db) {
  /* Two IPs sharing the same fingerprint should both show up under one
     find_by_fingerprint call.  That is the killer query for clustering. */
  CHECK(net_db_insert_fingerprint(db,
      ip_to_u32("10.0.0.2"), 443, "tls_sha256", "cohort_value", 3000) == 0);
  CHECK(net_db_insert_fingerprint(db,
      ip_to_u32("10.0.0.3"), 443, "tls_sha256", "cohort_value", 3000) == 0);

  auto matches = net_db_find_by_fingerprint(db, "tls_sha256", "cohort_value");
  CHECK(matches.size() == 2);
  std::set<uint32_t> seen;
  for (const auto &m : matches) seen.insert(m.ip_u32);
  CHECK(seen.count(ip_to_u32("10.0.0.2")) == 1);
  CHECK(seen.count(ip_to_u32("10.0.0.3")) == 1);
}

static void test_high_ip_roundtrip(sqlite3 *db) {
  /* 220.x.x.x is above INT_MAX as uint32 — the int64 binding must
     preserve it.  This is the exact bug that bit net_db_update_asn
     before its int64 fix; mirror the same check for fingerprints. */
  uint32_t hi_ip = ip_to_u32("220.10.20.30");
  CHECK(hi_ip > 0x80000000u);  /* genuinely above INT_MAX */

  CHECK(net_db_insert_fingerprint(db, hi_ip, 0, "hostname",
                                  "host.example.com", 4000) == 0);

  auto by_fp = net_db_find_by_fingerprint(db, "hostname", "host.example.com");
  CHECK(by_fp.size() == 1);
  if (!by_fp.empty()) {
    CHECK(by_fp[0].ip_u32 == hi_ip);
    CHECK(by_fp[0].port == 0);  /* port=0 stored as NULL, read back as 0 */
  }
}

static void test_per_ip_returns_all_kinds(sqlite3 *db) {
  /* One IP carrying multiple fingerprint kinds — forward lookup should
     return all of them. */
  uint32_t ip = ip_to_u32("10.0.0.42");
  CHECK(net_db_insert_fingerprint(db, ip, 443, "tls_sha256", "h1", 5000) == 0);
  CHECK(net_db_insert_fingerprint(db, ip, 443, "tls_san",    "a.com", 5000) == 0);
  CHECK(net_db_insert_fingerprint(db, ip, 0,   "hostname",   "x.com", 5000) == 0);

  auto by_ip = net_db_get_fingerprints_for_ip(db, "10.0.0.42");
  CHECK(by_ip.size() == 3);
  std::set<std::string> kinds;
  for (const auto &fp : by_ip) kinds.insert(fp.kind);
  CHECK(kinds.size() == 3);
  CHECK(kinds.count("tls_sha256") == 1);
  CHECK(kinds.count("tls_san")    == 1);
  CHECK(kinds.count("hostname")   == 1);
}

static void test_unknown_lookup_returns_empty(sqlite3 *db) {
  auto by_fp = net_db_find_by_fingerprint(db, "tls_sha256", "nope");
  CHECK(by_fp.empty());
  auto by_ip = net_db_get_fingerprints_for_ip(db, "99.99.99.99");
  CHECK(by_ip.empty());
}

static void test_bad_input_rejected(sqlite3 *db) {
  /* NULL kind/value and empty-string kind/value must all be rejected
     without corrupting the DB. */
  CHECK(net_db_insert_fingerprint(db, ip_to_u32("10.0.0.1"), 443,
                                  nullptr, "v", 1) == -1);
  CHECK(net_db_insert_fingerprint(db, ip_to_u32("10.0.0.1"), 443,
                                  "k", nullptr, 1) == -1);
  CHECK(net_db_insert_fingerprint(db, ip_to_u32("10.0.0.1"), 443,
                                  "", "v", 1) == -1);
  CHECK(net_db_insert_fingerprint(db, ip_to_u32("10.0.0.1"), 443,
                                  "k", "", 1) == -1);
}

int main() {
  /* Use a unique temp path so reruns do not collide.  time(NULL) is
     enough granularity for the rare case of back-to-back invocations. */
  std::string path = "/tmp/kmap_fp_test_" +
                     std::to_string(static_cast<long>(std::time(nullptr))) +
                     ".db";
  std::remove(path.c_str());

  sqlite3 *db = net_db_open(path);
  if (!db) {
    std::fprintf(stderr, "FATAL: net_db_open(%s) returned nullptr\n",
                 path.c_str());
    return 2;
  }

  test_insert_and_find_back(db);
  test_upsert_refreshes_observed_at(db);
  test_inverse_lookup_finds_cohort(db);
  test_high_ip_roundtrip(db);
  test_per_ip_returns_all_kinds(db);
  test_unknown_lookup_returns_empty(db);
  test_bad_input_rejected(db);

  net_db_close(db);
  std::remove(path.c_str());

  if (g_failures == 0) {
    std::printf("net_db_fingerprint_test: ALL PASS\n");
    return 0;
  } else {
    std::printf("net_db_fingerprint_test: %d FAIL\n", g_failures);
    return 1;
  }
}
