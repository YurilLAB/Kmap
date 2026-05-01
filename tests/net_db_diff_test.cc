/* net_db_diff_test.cc -- Unit tests for net_db's CVE parser + diff.
 *
 * Covers:
 *   - net_db_parse_cve_ids on the format produced by net_enrich's
 *     cves_to_json: empty / "[]" / single / multi / malformed inputs,
 *     IDs containing escaped quotes in the SAME entry's desc field,
 *     entries that lack an "id" key (skipped without breaking the parse).
 *   - net_db_cve_diff across the four interesting cases: no prior data,
 *     all patched (clean re-scan), partial patch, regression (new CVEs),
 *     and the persisting-only case where nothing changed.
 *   - Result lists are sorted ascending and de-duplicated.
 *
 * Pure C++; does NOT touch sqlite. The diff helpers in net_db.cc that
 * we test here do not call any sqlite3_* function so we link only the
 * two TUs needed (no sqlite amalgamation, no other kmap objects).
 */

#include "../net_db.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_failures = 0;

#define CHECK(expr) do { \
    if (!(expr)) { \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
      ++g_failures; \
    } \
  } while (0)

#define CHECK_EQ(a, b) do { \
    if (!((a) == (b))) { \
      std::fprintf(stderr, "FAIL %s:%d: %s != %s\n", \
                   __FILE__, __LINE__, #a, #b); \
      ++g_failures; \
    } \
  } while (0)

static bool vec_eq(const std::vector<std::string> &v,
                   std::initializer_list<const char *> expected) {
  if (v.size() != expected.size()) return false;
  size_t i = 0;
  for (const char *e : expected) {
    if (v[i++] != e) return false;
  }
  return true;
}

static void test_parse_empty(void) {
  CHECK(net_db_parse_cve_ids("").empty());
  CHECK(net_db_parse_cve_ids("[]").empty());
  /* Whitespace-only -- should still parse to empty without error. */
  CHECK(net_db_parse_cve_ids("   ").empty());
}

static void test_parse_single(void) {
  std::vector<std::string> ids = net_db_parse_cve_ids(
      "[{\"id\":\"CVE-2024-12345\",\"cvss\":7.5,\"severity\":\"HIGH\",\"desc\":\"x\"}]");
  CHECK(vec_eq(ids, {"CVE-2024-12345"}));
}

static void test_parse_multi(void) {
  std::vector<std::string> ids = net_db_parse_cve_ids(
      "[{\"id\":\"CVE-2018-15473\",\"cvss\":5.3,\"severity\":\"MEDIUM\",\"desc\":\"\"},"
      "{\"id\":\"CVE-2020-14145\",\"cvss\":5.9,\"severity\":\"MEDIUM\",\"desc\":\"\"},"
      "{\"id\":\"CVE-2023-38408\",\"cvss\":9.8,\"severity\":\"CRITICAL\",\"desc\":\"\"}]");
  /* Order matches input -- the parser preserves the array order; the diff
   * function does the sort. */
  CHECK(vec_eq(ids, {"CVE-2018-15473", "CVE-2020-14145", "CVE-2023-38408"}));
}

static void test_parse_with_escaped_quotes(void) {
  /* Description containing an escaped quote must not desync the parser.
   * The desc field comes AFTER id, so even a naive parser handles this,
   * but exercise it as a regression guard. */
  std::vector<std::string> ids = net_db_parse_cve_ids(
      "[{\"id\":\"CVE-2024-1\",\"cvss\":1.0,\"severity\":\"LOW\","
      "\"desc\":\"contains \\\" a quote\"}]");
  CHECK(vec_eq(ids, {"CVE-2024-1"}));
}

static void test_parse_missing_id(void) {
  /* An entry without an "id" key is skipped; siblings with an id still
   * parse cleanly. This protects against future format extensions where
   * a non-CVE entry slips into the array. */
  std::vector<std::string> ids = net_db_parse_cve_ids(
      "[{\"cvss\":5.0,\"severity\":\"LOW\",\"desc\":\"no id\"},"
      "{\"id\":\"CVE-2024-99\",\"cvss\":7.0,\"severity\":\"HIGH\",\"desc\":\"\"}]");
  CHECK(vec_eq(ids, {"CVE-2024-99"}));
}

static void test_parse_malformed(void) {
  /* Truncated JSON should not crash and should return an empty or
   * partial result (whatever was parseable up to the truncation). */
  CHECK(net_db_parse_cve_ids("[{\"id\":\"CVE-").empty());
  CHECK(net_db_parse_cve_ids("garbage").empty());
}

static void test_diff_first_scan(void) {
  /* No prior data -- everything in current is "introduced", nothing is
   * "patched". This is the steady state for a host's first enrichment. */
  NetDbCveDiff d = net_db_cve_diff(
      "",
      "[{\"id\":\"CVE-2024-1\",\"cvss\":7.5,\"severity\":\"HIGH\",\"desc\":\"\"},"
      "{\"id\":\"CVE-2024-2\",\"cvss\":5.0,\"severity\":\"MEDIUM\",\"desc\":\"\"}]");
  CHECK(d.patched.empty());
  CHECK(d.persisting.empty());
  CHECK(vec_eq(d.introduced, {"CVE-2024-1", "CVE-2024-2"}));
}

static void test_diff_all_patched(void) {
  /* Re-scan finds no CVEs; every prior CVE moves to "patched". This is
   * the headline case the patch-status feature exists to surface. */
  NetDbCveDiff d = net_db_cve_diff(
      "[{\"id\":\"CVE-2018-15473\",\"cvss\":5.3,\"severity\":\"MEDIUM\",\"desc\":\"\"},"
      "{\"id\":\"CVE-2020-14145\",\"cvss\":5.9,\"severity\":\"MEDIUM\",\"desc\":\"\"}]",
      "");
  CHECK(vec_eq(d.patched, {"CVE-2018-15473", "CVE-2020-14145"}));
  CHECK(d.persisting.empty());
  CHECK(d.introduced.empty());
}

static void test_diff_partial_patch(void) {
  /* One CVE patched, one new, one persistent. Output must split them
   * correctly even when input order differs from sorted order. */
  NetDbCveDiff d = net_db_cve_diff(
      "[{\"id\":\"CVE-2020-14145\",\"cvss\":5.9,\"severity\":\"MEDIUM\",\"desc\":\"\"},"
      "{\"id\":\"CVE-2018-15473\",\"cvss\":5.3,\"severity\":\"MEDIUM\",\"desc\":\"\"}]",
      "[{\"id\":\"CVE-2020-14145\",\"cvss\":5.9,\"severity\":\"MEDIUM\",\"desc\":\"\"},"
      "{\"id\":\"CVE-2024-9999\",\"cvss\":9.0,\"severity\":\"CRITICAL\",\"desc\":\"\"}]");
  CHECK(vec_eq(d.patched,    {"CVE-2018-15473"}));
  CHECK(vec_eq(d.persisting, {"CVE-2020-14145"}));
  CHECK(vec_eq(d.introduced, {"CVE-2024-9999"}));
}

static void test_diff_no_change(void) {
  /* Same CVE list both scans -- everything persists, nothing patched
   * or introduced. The order of duplicates in the input must not
   * confuse the merge. */
  NetDbCveDiff d = net_db_cve_diff(
      "[{\"id\":\"CVE-2020-14145\",\"cvss\":5.9,\"severity\":\"M\",\"desc\":\"\"},"
      "{\"id\":\"CVE-2018-15473\",\"cvss\":5.3,\"severity\":\"M\",\"desc\":\"\"}]",
      "[{\"id\":\"CVE-2018-15473\",\"cvss\":5.3,\"severity\":\"M\",\"desc\":\"\"},"
      "{\"id\":\"CVE-2020-14145\",\"cvss\":5.9,\"severity\":\"M\",\"desc\":\"\"}]");
  CHECK(d.patched.empty());
  CHECK(vec_eq(d.persisting, {"CVE-2018-15473", "CVE-2020-14145"}));
  CHECK(d.introduced.empty());
}

static void test_diff_dedupes(void) {
  /* Duplicate IDs in the input array (a corruption case) must collapse
   * to a single entry in each output list -- otherwise summary counts
   * would be inflated by the duplication. */
  NetDbCveDiff d = net_db_cve_diff(
      "[{\"id\":\"CVE-1\",\"cvss\":1.0,\"severity\":\"L\",\"desc\":\"\"},"
      "{\"id\":\"CVE-1\",\"cvss\":1.0,\"severity\":\"L\",\"desc\":\"\"}]",
      "[{\"id\":\"CVE-1\",\"cvss\":1.0,\"severity\":\"L\",\"desc\":\"\"}]");
  CHECK(d.patched.empty());
  CHECK(vec_eq(d.persisting, {"CVE-1"}));
  CHECK(d.introduced.empty());
}

static void test_diff_sorted_output(void) {
  /* Output lists are sorted ascending so report rendering is stable
   * and grep-friendly. Feed input in reverse order and verify the
   * output is forward-sorted. */
  NetDbCveDiff d = net_db_cve_diff(
      "",
      "[{\"id\":\"CVE-2024-9\",\"cvss\":7.0,\"severity\":\"H\",\"desc\":\"\"},"
      "{\"id\":\"CVE-2024-2\",\"cvss\":5.0,\"severity\":\"M\",\"desc\":\"\"},"
      "{\"id\":\"CVE-2024-5\",\"cvss\":6.0,\"severity\":\"M\",\"desc\":\"\"}]");
  CHECK(vec_eq(d.introduced, {"CVE-2024-2", "CVE-2024-5", "CVE-2024-9"}));
}

int main(void) {
  test_parse_empty();
  test_parse_single();
  test_parse_multi();
  test_parse_with_escaped_quotes();
  test_parse_missing_id();
  test_parse_malformed();

  test_diff_first_scan();
  test_diff_all_patched();
  test_diff_partial_patch();
  test_diff_no_change();
  test_diff_dedupes();
  test_diff_sorted_output();

  if (g_failures) {
    std::fprintf(stderr, "net_db_diff_test: %d FAILURE(S)\n", g_failures);
    return 1;
  }
  std::printf("net_db_diff_test: all tests passed\n");
  return 0;
}
