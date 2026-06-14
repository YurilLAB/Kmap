/*
 * test_watchlist_diff.cc -- correctness model for the watchlist diff report
 * (run_watchlist in net_scan.cc): [NEW PORT], [CHANGED], [CLOSED].
 *
 * Replicates the diff set logic (keyed by ip:port) so the NEW/CHANGED/CLOSED
 * classification can be verified against an independent oracle without a live
 * scan. The [CHANGED] branch was added to emit service/version drift for a
 * port open in both scans; this test pins that behaviour plus the existing
 * NEW/CLOSED semantics, including the "don't report a change when the new
 * value is empty (transient enrichment miss)" guard.
 *
 * Build: g++ -O2 -g -std=gnu++17 -Wall fuzz/test_watchlist_diff.cc \
 *        -o fuzz/test_watchlist_diff.exe && fuzz/test_watchlist_diff.exe
 */
#include <cstdio>
#include <string>
#include <vector>
#include <set>
#include <map>

struct Row { std::string ip; int port; std::string service; std::string version; };

struct Diff { std::vector<std::string> neu, changed, closed; };

/* Mirrors the net_scan.cc diff loop. */
static Diff compute_diff(const std::vector<Row> &prev, const std::vector<Row> &cur) {
  Diff d;
  std::set<std::string> prev_keys, curr_keys;
  std::map<std::string, std::string> prev_svc, prev_ver;
  auto K = [](const Row &r) { return r.ip + ":" + std::to_string(r.port); };
  for (const auto &pe : prev) {
    std::string k = K(pe); prev_keys.insert(k);
    prev_svc[k] = pe.service; prev_ver[k] = pe.version;
  }
  for (const auto &h : cur) curr_keys.insert(K(h));

  for (const auto &h : cur) {
    std::string k = K(h);
    if (prev_keys.find(k) == prev_keys.end()) {
      d.neu.push_back(k);
    } else {
      const std::string &ps = prev_svc[k], &pv = prev_ver[k];
      bool sc = !h.service.empty() && h.service != ps;
      bool vc = !h.version.empty() && h.version != pv;
      if (sc || vc) d.changed.push_back(k);
    }
  }
  for (const auto &pe : prev) {
    std::string k = K(pe);
    if (curr_keys.find(k) == curr_keys.end()) d.closed.push_back(k);
  }
  return d;
}

static int g_fail = 0;
static void expect(bool cond, const char *what) {
  if (!cond) { printf("  FAIL: %s\n", what); g_fail++; }
}

int main(void) {
  printf("watchlist diff model test\n=========================\n");

  /* prev: 1.1.1.1:80 nginx 1.18, 1.1.1.1:443 nginx 1.18, 2.2.2.2:22 openssh 8.2
     cur:  1.1.1.1:80 nginx 1.25 (version changed),
           1.1.1.1:8080 (new),
           2.2.2.2:22 openssh 8.2 (unchanged),
           -- 1.1.1.1:443 absent (closed) */
  std::vector<Row> prev = {
    {"1.1.1.1",80,"nginx","1.18"}, {"1.1.1.1",443,"nginx","1.18"},
    {"2.2.2.2",22,"openssh","8.2"}
  };
  std::vector<Row> cur = {
    {"1.1.1.1",80,"nginx","1.25"}, {"1.1.1.1",8080,"http",""},
    {"2.2.2.2",22,"openssh","8.2"}
  };
  Diff d = compute_diff(prev, cur);

  expect(d.neu.size()==1 && d.neu[0]=="1.1.1.1:8080", "NEW = 1.1.1.1:8080");
  expect(d.changed.size()==1 && d.changed[0]=="1.1.1.1:80", "CHANGED = 1.1.1.1:80 (version)");
  expect(d.closed.size()==1 && d.closed[0]=="1.1.1.1:443", "CLOSED = 1.1.1.1:443");

  /* Transient enrichment miss: same port open in both, but cur service/version
     empty -> must NOT be reported as changed. */
  Diff d2 = compute_diff(
    {{"3.3.3.3",80,"nginx","1.18"}},
    {{"3.3.3.3",80,"",""}});
  expect(d2.changed.empty(), "empty new svc/ver is not a change");
  expect(d2.neu.empty() && d2.closed.empty(), "still-open port is not new/closed");

  /* Service repurpose: same port, service changes ssh->http. */
  Diff d3 = compute_diff(
    {{"4.4.4.4",2222,"ssh","openssh 8.2"}},
    {{"4.4.4.4",2222,"http","nginx 1.25"}});
  expect(d3.changed.size()==1, "service repurpose flagged changed");

  /* No-change run: identical prev/cur -> zero diff. */
  Diff d4 = compute_diff(prev, prev);
  expect(d4.neu.empty() && d4.changed.empty() && d4.closed.empty(), "identical scans -> no diff");

  /* --- prev_state gating model (the [CLOSED]-staleness fix) ---
     The DB is cumulative; prev_state is scoped to rows with
     last_seen >= prev_scan_ts (the previous run). A port that went dark BEFORE
     the previous run is NOT in the gated prev set, so it is not re-reported
     [CLOSED] every run. */
  struct RowTs { std::string ip; int port; std::string svc; std::string ver; long last_seen; };
  auto gate = [](const std::vector<RowTs> &rows, long prev_scan_ts) {
    std::vector<Row> out;
    for (const auto &r : rows)
      if (prev_scan_ts == 0 || r.last_seen >= prev_scan_ts)
        out.push_back({r.ip, r.port, r.svc, r.ver});
    return out;
  };
  /* Timeline: run@100 opened :80 and :443. run@200 :443 closed (last_seen of
     :443 stays 100; :80 refreshed to 200). Now run@300: prev_scan_ts=200. */
  std::vector<RowTs> db = {
    {"5.5.5.5",80,"nginx","1.0",200},   /* still open at run@200 */
    {"5.5.5.5",443,"nginx","1.0",100},  /* went dark at run@200, last_seen frozen at 100 */
  };
  long prev_scan_ts = 200;              /* boundary = previous (run@200) start */
  std::vector<Row> gated_prev = gate(db, prev_scan_ts);
  std::vector<Row> cur_300 = {{"5.5.5.5",80,"nginx","1.0"}};  /* run@300 finds :80 only */
  Diff d5 = compute_diff(gated_prev, cur_300);
  expect(d5.closed.empty(),
         ":443 (closed before prev run) is NOT re-reported [CLOSED]");
  expect(d5.neu.empty() && d5.changed.empty(), "stable :80 -> no spurious diff at run@300");

  /* Contrast: WITHOUT gating (prev_scan_ts=0, the old all-history behavior)
     :443 WOULD be re-reported [CLOSED] -- demonstrates the bug the gate fixes. */
  Diff d6 = compute_diff(gate(db, 0), cur_300);
  expect(d6.closed.size()==1 && d6.closed[0]=="5.5.5.5:443",
         "ungated (old behavior) re-reports the stale [CLOSED] -- bug confirmed");

  printf("%s\n", g_fail==0 ? "watchlist-diff test: ALL PASS" : "watchlist-diff test: FAILURES");
  return g_fail==0 ? 0 : 1;
}
