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
  remove("test_netdb.db");
  return fails ? 1 : 0;
}
