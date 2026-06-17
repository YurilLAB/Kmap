/* test_netdb.cc -- LIVE test of the net_db.cc sqlite scan store.
 *
 * Links the REAL net_db.cc + sqlite and exercises the rescan/history
 * invariants the skill flags as the most damage-prone area:
 *   - cumulative hosts table (first_seen anchored, last_seen refreshed,
 *     scan_count bumped on re-discovery)
 *   - re-enrichment gate (enriched=0 OR last_seen > enriched_at)
 *   - prev_* snapshot capture on re-enrichment
 *   - COALESCE preserves prior good data when a field is passed NULL
 *   - net_db_cve_diff introduced/patched sets
 *
 * Build (from fuzz/; the committed ../sqlite/sqlite3.o is a Linux object, so on
 * Windows/MinGW compile the amalgamation fresh first):
 *   gcc -O1 -c ../sqlite/sqlite3.c -o sqlite3_win.o
 *   g++ -O2 -std=gnu++17 -I.. test_netdb.cc ../net_db.cc sqlite3_win.o -o test_netdb.exe
 * On Linux just link ../sqlite/sqlite3.o directly.
 */
#include "net_db.h"
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <ctime>

static int fails = 0, passes = 0;
#define CHECK(cond, msg) do { if (cond) { passes++; } \
  else { printf("  FAIL: %s\n", msg); fails++; } } while (0)

static NetHost getrow(sqlite3 *db, const char *ip, int port) {
  for (auto &h : net_db_get_host(db, ip)) if (h.port == port) return h;
  NetHost empty{}; empty.port = -1; return empty;
}

int main() {
  remove("test_netdb.db");
  sqlite3 *db = net_db_open("test_netdb.db");
  if (!db) { printf("net_db_open FAILED\n"); return 2; }

  uint32_t ip = ip_to_u32("203.0.113.5");
  const char *IP = "203.0.113.5";
  int64_t t0 = (int64_t)time(nullptr);

  /* ---- Scan 1: discovery ---- */
  net_db_insert_host(db, ip, 80,  "tcp", t0 + 10);
  net_db_insert_host(db, ip, 443, "tcp", t0 + 10);
  NetHost r = getrow(db, IP, 80);
  CHECK(r.port == 80,                 "port 80 row exists after insert");
  CHECK(r.scan_count == 1,            "scan_count=1 on first sight");
  CHECK(r.first_seen == t0 + 10,      "first_seen set to insert ts");
  CHECK(r.last_seen  == t0 + 10,      "last_seen set to insert ts");
  CHECK(r.enriched == 0,              "enriched=0 before enrichment");

  auto un = net_db_get_unenriched(db, 100);
  CHECK(un.size() == 1 && un[0] == IP, "fresh host listed as unenriched");

  /* ---- Enrich #1 ---- */
  net_db_update_enrichment(db, IP, 80, "ssh", "7.4",
                           "[{\"id\":\"CVE-2016-0777\"}]",
                           "OldTitle", "OpenSSH", "{}", "[]");
  r = getrow(db, IP, 80);
  CHECK(r.enriched == 1,                  "enriched=1 after update");
  CHECK(r.service == "ssh",               "service stored");
  CHECK(r.version == "7.4",               "version stored");
  CHECK(r.web_title == "OldTitle",        "web_title stored");
  CHECK(r.prev_service.empty(),           "prev_service empty on first enrichment");
  CHECK(r.prev_version.empty(),           "prev_version empty on first enrichment");

  /* The IP still has port 443 unenriched, so get_unenriched correctly still
     lists it. Enrich 443 too, THEN it should drop out (all ports enriched,
     last_seen==enriched_at on both). */
  net_db_update_enrichment(db, IP, 443, "https", "1.1", "[]",
                           "T2", "nginx", "{}", "[]");
  un = net_db_get_unenriched(db, 100);
  CHECK(un.empty(), "host drops from unenriched once all ports enriched");

  /* ---- Scan 2: re-discovery (future ts) ---- */
  net_db_insert_host(db, ip, 80, "tcp", t0 + 1000);
  r = getrow(db, IP, 80);
  CHECK(r.scan_count == 2,            "scan_count bumped to 2 on rescan");
  CHECK(r.first_seen == t0 + 10,     "first_seen PRESERVED across rescan");
  CHECK(r.last_seen  == t0 + 1000,   "last_seen advanced on rescan");

  un = net_db_get_unenriched(db, 100);
  CHECK(!un.empty(), "rescanned host (last_seen>enriched_at) eligible to re-enrich");

  /* ---- Enrich #2: new version/cves, NULL web_title (COALESCE) ---- */
  net_db_update_enrichment(db, IP, 80, "ssh", "8.0",
                           "[{\"id\":\"CVE-2023-9999\"}]",
                           nullptr /* web_title NULL */, "OpenSSH", "{}", "[]");
  r = getrow(db, IP, 80);
  CHECK(r.version == "8.0",                              "version updated on re-enrich");
  CHECK(r.prev_version == "7.4",                         "prev_version captured old value");
  CHECK(r.prev_service == "ssh",                         "prev_service captured");
  CHECK(r.prev_cves.find("CVE-2016-0777") != std::string::npos,
                                                         "prev_cves captured old CVE");
  CHECK(r.cves.find("CVE-2023-9999") != std::string::npos,
                                                         "cves updated to new CVE");
  CHECK(r.web_title == "OldTitle",
        "COALESCE: NULL web_title preserved prior value (no data wipe)");

  /* ---- CVE diff ---- */
  NetDbCveDiff d = net_db_cve_diff(r.prev_cves, r.cves);
  bool intro = false, patched = false;
  for (auto &s : d.introduced) if (s.find("CVE-2023-9999") != std::string::npos) intro = true;
  for (auto &s : d.patched)    if (s.find("CVE-2016-0777") != std::string::npos) patched = true;
  CHECK(intro,   "cve_diff: new CVE in introduced[]");
  CHECK(patched, "cve_diff: old CVE in patched[]");

  /* ---- isolation: port 443 not affected by port-80's rescan/re-enrich ---- */
  NetHost r443 = getrow(db, IP, 443);
  CHECK(r443.scan_count == 1,    "port 443 scan_count still 1 (only port 80 rescanned)");
  CHECK(r443.version == "1.1",   "port 443 version unchanged by port-80 re-enrich");
  CHECK(r443.prev_version.empty(),"port 443 prev_* untouched (enriched once)");

  /* ---- net_db_update_asn COALESCE (protects the ASN-wipe fix) ----
     Team Cymru returns asn/bgp/country together but as_name comes from a
     SEPARATE query that can fail, so a re-lookup can arrive with asn>0 and an
     empty as_name. The fix COALESCEs every text field so a partial result
     never erases previously-captured ASN data. */
  {
    uint32_t aip = ip_to_u32("198.51.100.7");
    const char *AIP = "198.51.100.7";
    net_db_insert_host(db, aip, 80, "tcp", t0 + 10);
    net_db_update_asn(db, AIP, 15169, "GOOGLE", "US", "8.8.8.0/24",
                      "arin", "North America");
    NetHost a = getrow(db, AIP, 80);
    CHECK(a.asn == 15169,               "asn stored");
    CHECK(a.as_name == "GOOGLE",        "as_name stored");
    CHECK(a.country == "US",            "country stored");
    CHECK(a.bgp_prefix == "8.8.8.0/24", "bgp_prefix stored");

    /* Partial re-lookup: asn present, as_name/country/bgp empty -> prior
       values must survive (this is the regression the fix prevents). */
    net_db_update_asn(db, AIP, 15169, "", "", "", "", "");
    a = getrow(db, AIP, 80);
    CHECK(a.as_name == "GOOGLE",        "as_name PRESERVED on partial re-lookup (no wipe)");
    CHECK(a.country == "US",            "country PRESERVED on partial re-lookup");
    CHECK(a.bgp_prefix == "8.8.8.0/24", "bgp_prefix PRESERVED on partial re-lookup");
    CHECK(a.asn == 15169,               "asn retained");

    /* A non-empty new as_name DOES overwrite. */
    net_db_update_asn(db, AIP, 15169, "GOOGLE-LLC", "", "", "", "");
    a = getrow(db, AIP, 80);
    CHECK(a.as_name == "GOOGLE-LLC",    "non-empty as_name overwrites");
    CHECK(a.country == "US",            "country still preserved alongside as_name update");

    /* 4-byte ASN (> INT_MAX) must round-trip without truncation (int64 bind). */
    net_db_update_asn(db, AIP, 4000000000u, "BIGAS", "", "", "", "");
    a = getrow(db, AIP, 80);
    CHECK(a.asn == 4000000000u,         "4-byte ASN (>INT_MAX) not truncated");
  }

  /* ---- v5e cpe column round-trip (fresh IP so it can't disturb the
     port-80 state machine above).  Pins the net_db_update_enrichment bind
     renumber: cpe=12, ip=13, port=14.  If ip/port were mis-bound the UPDATE
     WHERE would not match and the cpe would never land on this row. ---- */
  {
    uint32_t cip = ip_to_u32("198.51.100.42");
    const char *CIP = "198.51.100.42";
    net_db_insert_host(db, cip, 22, "tcp", t0 + 10);
    net_db_update_enrichment(db, CIP, 22, "ssh", "8.0",
                             "[]", nullptr, "OpenSSH", "{}", "[]",
                             nullptr, nullptr, nullptr, nullptr,
                             "cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*");
    NetHost c = getrow(db, CIP, 22);
    CHECK(c.cpe == "cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*",
          "cpe stored + read back on the correct (ip,port) row");
    /* NULL cpe must COALESCE-preserve the prior value (no wipe on a later
       enrichment that didn't resolve a product). */
    net_db_update_enrichment(db, CIP, 22, "ssh", "8.0", "[]",
                             nullptr, "OpenSSH", "{}", "[]");
    c = getrow(db, CIP, 22);
    CHECK(c.cpe == "cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*",
          "COALESCE: NULL cpe preserved prior value");
  }

  /* ---- v5f cloud-provider columns round-trip + COALESCE (fresh IP). ---- */
  {
    uint32_t kip = ip_to_u32("198.51.100.55");
    const char *KIP = "198.51.100.55";
    net_db_insert_host(db, kip, 443, "tcp", t0 + 10);
    net_db_update_cloud(db, KIP, "aws", "us-east-1", "EC2");
    NetHost c = getrow(db, KIP, 443);
    CHECK(c.cloud_provider == "aws",        "cloud_provider stored");
    CHECK(c.cloud_region   == "us-east-1",  "cloud_region stored");
    CHECK(c.cloud_service  == "EC2",        "cloud_service stored");
    /* NULL/empty re-match must preserve (COALESCE), not wipe. */
    net_db_update_cloud(db, KIP, nullptr, nullptr, nullptr);
    c = getrow(db, KIP, 443);
    CHECK(c.cloud_provider == "aws",        "COALESCE: NULL provider preserved");
    CHECK(c.cloud_region   == "us-east-1",  "COALESCE: NULL region preserved");
    /* a non-empty new provider overwrites. */
    net_db_update_cloud(db, KIP, "gcp", nullptr, nullptr);
    c = getrow(db, KIP, 443);
    CHECK(c.cloud_provider == "gcp",        "non-empty provider overwrites");
    CHECK(c.cloud_region   == "us-east-1",  "region preserved alongside provider update");
  }

  /* ---- enrichment error cooldown round-trip ----
     A host whose enrichment errored must be parked out of the eligible pool
     for retry_after_seconds (so a dead host isn't hammered every pass) and
     then become eligible again (so it IS eventually retried). A success clears
     the error. Verifies record_enrichment_error + the cooldown leg of the
     get_unenriched predicate + the success-clears-error path. */
  {
    uint32_t eip = ip_to_u32("198.51.100.23");
    const char *EIP = "198.51.100.23";
    int64_t base = (int64_t)time(nullptr);
    net_db_insert_host(db, eip, 22, "tcp", base);
    auto has = [&](const std::vector<std::string> &v) {
      for (const auto &i : v) if (i == EIP) return true; return false; };

    CHECK(has(net_db_get_unenriched(db, 100000, 3600)),
          "fresh host eligible before any error");
    net_db_record_enrichment_error(db, EIP, 22, "connect timeout");
    CHECK(!has(net_db_get_unenriched(db, 100000, 3600)),
          "errored host parked OUT of pool during cooldown");
    CHECK(has(net_db_get_unenriched(db, 100000, 0)),
          "errored host eligible again once cooldown elapses (retry)");
    net_db_update_enrichment(db, EIP, 22, "ssh", "9.1", "[]",
                             "t", "OpenSSH", "{}", "[]");
    CHECK(!has(net_db_get_unenriched(db, 100000, 0)),
          "host drops out after a successful enrichment (error cleared)");
    CHECK(getrow(db, EIP, 22).enriched == 1,
          "enriched=1 after success following an error");
  }

  /* ---- drain-loop invariant: net_db_count_unenriched() and
     net_db_get_unenriched() must agree on whether work remains. run_net_scan's
     Phase-2 loop runs `while (count_unenriched_all() > 0) run_enrichment()`,
     where run_enrichment pulls work via get_unenriched. If the two predicates
     (or their NET_DB_ENRICH_RETRY_SECONDS cooldown defaults) ever diverge the
     loop spins forever (count>0, get empty) or stops with eligible rows left
     (count==0, get non-empty). Pin the lockstep here against the live DB. ---- */
  {
    int64_t cnt = net_db_count_unenriched(db);
    auto ids = net_db_get_unenriched(db, 100000);
    CHECK((cnt == 0) == ids.empty(),
          "count_unenriched()==0 iff get_unenriched() empty (drain terminates)");
    CHECK((int64_t)ids.size() <= cnt,
          "distinct unenriched IPs <= unenriched row count");

    /* Fresh host (own timestamps, independent of the future-ts rows above):
       counted + listed when new, and drops from BOTH once fully enriched. */
    uint32_t ip2 = ip_to_u32("203.0.113.9");
    const char *IP2 = "203.0.113.9";
    int64_t base = (int64_t)time(nullptr);
    net_db_insert_host(db, ip2, 22, "tcp", base);
    int64_t cnt_new = net_db_count_unenriched(db);
    auto ids_new = net_db_get_unenriched(db, 100000);
    bool listed = false; for (auto &i : ids_new) if (i == IP2) listed = true;
    CHECK(cnt_new >= 1 && listed, "fresh host counted and listed as unenriched");
    CHECK((cnt_new == 0) == ids_new.empty(), "count/get agree with fresh host present");

    net_db_update_enrichment(db, IP2, 22, "ssh", "9.0", "[]",
                             "t", "OpenSSH", "{}", "[]");
    auto ids_enr = net_db_get_unenriched(db, 100000);
    bool still = false; for (auto &i : ids_enr) if (i == IP2) still = true;
    CHECK(!still, "fully-enriched fresh host drops out of get_unenriched");
    CHECK((net_db_count_unenriched(db) == 0) == ids_enr.empty(),
          "count/get still agree after enriching the fresh host");
  }

  printf("\nnet_db live test: %d passed, %d failed\n", passes, fails);
  net_db_close(db);   /* close the connection so LeakSanitizer sees no leak --
                         net_db_count_unenriched's COUNT(DISTINCT ip) holds a
                         temp b-tree on the connection (temp_store=MEMORY) that
                         is only freed on close; the real code always closes its
                         shards (close_all_shards). */
  remove("test_netdb.db");
  return fails ? 1 : 0;
}
